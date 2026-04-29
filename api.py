from __future__ import annotations

from flask import Blueprint, jsonify, request

from CTFd.models import Challenges, Solves, Users, db
from CTFd.utils.decorators import authed_only, ratelimit
from CTFd.utils.user import get_current_user

try:
    from CTFd.utils.config import is_teams_mode
except Exception:
    is_teams_mode = None

try:
    from CTFd.utils.user import get_current_team
except Exception:
    get_current_team = None

from .models import Module, ModuleCategory, ModuleChallenge, ModuleStatus
from .compat import csrf_protect
from .utils import (
    ensure_private_invite_code,
    module_challenges_query,
    module_progress,
    user_has_module_access,
    grant_access,
    modules_enabled,
    ordered_modules_query,
    ordered_categories_query,
)


modules_api_bp = Blueprint("ctfd_modules_api", __name__, url_prefix="/api/v1/modules")


def _modules_disabled_response():
    return jsonify({"success": False, "error": "MODULES_DISABLED"}), 404


def _ensure_modules_enabled():
    if modules_enabled():
        return None
    return _modules_disabled_response()


def _forbidden_response():
    return jsonify({"success": False, "error": "FORBIDDEN"}), 403


def _module_access_error(module: Module, user: Users | None):
    if module.status == ModuleStatus.locked:
        return jsonify({"success": False, "error": "MODULE_LOCKED"}), 403
    if module.status == ModuleStatus.private and not user_has_module_access(user, module):
        return jsonify({"success": False, "error": "MODULE_ACCESS_REQUIRED"}), 403
    return None


def _solved_ids_for_user(user: Users | None) -> set[int]:
    if not user:
        return set()

    try:
        if is_teams_mode and is_teams_mode() and get_current_team:
            team = get_current_team()
            if team:
                return {
                    cid
                    for (cid,) in db.session.query(Solves.challenge_id)
                    .filter(Solves.team_id == team.id)
                    .all()
                }
    except Exception:
        pass

    return {
        cid
        for (cid,) in db.session.query(Solves.challenge_id)
        .filter(Solves.user_id == user.id)
        .all()
    }


def _module_to_dict(module: Module, user: Users | None):
    has_access = user_has_module_access(user, module) if user else False
    progress = module_progress(user, module) if has_access else module_progress(None, module, challenge_ids=[])
    return {
        "id": module.id,
        "name": module.name,
        "category": module.category,
        "banner_url": module.banner_url,
        "order": module.order,
        "status": module.status.value if hasattr(module.status, "value") else str(module.status),
        "created_at": module.created_at.isoformat() if module.created_at else None,
        "updated_at": module.updated_at.isoformat() if module.updated_at else None,
        "has_access": has_access,
        "progress": progress,
    }


@modules_api_bp.route("", methods=["GET"])
@authed_only
def api_modules_list():
    disabled = _ensure_modules_enabled()
    if disabled:
        return disabled

    user = get_current_user()
    modules = ordered_modules_query().all()
    # Locked modules are not visible via list for anyone.
    modules = [m for m in modules if m.status != ModuleStatus.locked]

    # Private modules should not appear in the general list unless the user has access.
    modules = [
        m
        for m in modules
        if m.status == ModuleStatus.public
        or (m.status == ModuleStatus.private and user_has_module_access(user, m))
    ]

    return jsonify({"success": True, "data": [_module_to_dict(m, user) for m in modules]})


@modules_api_bp.route("/<int:module_id>", methods=["GET"])
@authed_only
def api_modules_get(module_id: int):
    disabled = _ensure_modules_enabled()
    if disabled:
        return disabled

    user = get_current_user()
    module = Module.query.get_or_404(module_id)
    access_error = _module_access_error(module, user)
    if access_error:
        return access_error

    return jsonify({"success": True, "data": _module_to_dict(module, user)})


@modules_api_bp.route("/<int:module_id>/join", methods=["POST"])
@authed_only
@ratelimit(method="POST", limit=10, interval=60)
@csrf_protect
def api_modules_join(module_id: int):
    disabled = _ensure_modules_enabled()
    if disabled:
        return disabled

    user = get_current_user()
    module = Module.query.get_or_404(module_id)

    if module.status != ModuleStatus.private:
        return jsonify({"success": False, "error": "MODULE_NOT_PRIVATE"}), 400

    body = request.get_json(silent=True) or {}
    code = (body.get("invite_code") or "").strip().upper()
    if not code or not module.invite_code or code != module.invite_code:
        return jsonify({"success": False, "error": "INVALID_INVITE_CODE"}), 400

    grant_access(module, user, granted_by_user=None)
    db.session.commit()

    return jsonify({"success": True, "data": _module_to_dict(module, user)})


@modules_api_bp.route("/<int:module_id>/challenges", methods=["GET"])
@authed_only
def api_modules_challenges(module_id: int):
    disabled = _ensure_modules_enabled()
    if disabled:
        return disabled

    user = get_current_user()
    module = Module.query.get_or_404(module_id)
    access_error = _module_access_error(module, user)
    if access_error:
        return access_error

    challenges = module_challenges_query(module, include_hidden=False)
    if not challenges:
        return jsonify({"success": False, "error": "MODULE_EMPTY"}), 404

    solved_ids = _solved_ids_for_user(user)

    data = []
    for c in challenges:
        data.append(
            {
                "id": c.id,
                "name": c.name,
                "category": c.category,
                "value": c.value,
                "state": c.state,
                "type": c.type,
                "solved": c.id in solved_ids,
            }
        )

    return jsonify({"success": True, "data": data})


@modules_api_bp.route("/assign", methods=["POST"])
@authed_only
@csrf_protect
def api_modules_assign_challenge():
    disabled = _ensure_modules_enabled()
    if disabled:
        return disabled

    user = get_current_user()
    if not user or getattr(user, "type", None) != "admin":
        return _forbidden_response()

    body = request.get_json(silent=True) or {}
    challenge_id = body.get("challenge_id")
    try:
        challenge_id = int(challenge_id)
    except Exception:
        return jsonify({"success": False, "error": "INVALID_PAYLOAD"}), 400

    raw_module_ids = body.get("module_ids")
    module_ids: list[int] = []
    if isinstance(raw_module_ids, list):
        for value in raw_module_ids:
            try:
                module_ids.append(int(value))
            except Exception:
                continue
    elif body.get("module_id") not in (None, ""):
        try:
            module_ids = [int(body.get("module_id"))]
        except Exception:
            return jsonify({"success": False, "error": "INVALID_PAYLOAD"}), 400

    module_ids = list(dict.fromkeys([mid for mid in module_ids if mid > 0]))

    if not Challenges.query.get(challenge_id):
        return jsonify({"success": False, "error": "CHALLENGE_NOT_FOUND"}), 404

    if not module_ids and "module_ids" in body:
        ModuleChallenge.query.filter_by(challenge_id=challenge_id).delete()
        db.session.commit()
        return jsonify({"success": True, "data": {"challenge_id": challenge_id, "module_ids": []}})

    if not module_ids:
        return jsonify({"success": False, "error": "INVALID_PAYLOAD"}), 400

    # Validate existence
    existing_modules = {
        mid
        for (mid,) in db.session.query(Module.id).filter(Module.id.in_(module_ids)).all()
    }
    if len(existing_modules) != len(module_ids):
        return jsonify({"success": False, "error": "MODULE_NOT_FOUND"}), 404

    if isinstance(raw_module_ids, list):
        ModuleChallenge.query.filter_by(challenge_id=challenge_id).delete()

    existing_links = {
        mid
        for (mid,) in db.session.query(ModuleChallenge.module_id)
        .filter(ModuleChallenge.challenge_id == challenge_id)
        .all()
    }
    for module_id in module_ids:
        if module_id in existing_links:
            continue
        db.session.add(ModuleChallenge(challenge_id=challenge_id, module_id=module_id))

    db.session.commit()
    return jsonify({"success": True, "data": {"challenge_id": challenge_id, "module_ids": module_ids}})


@modules_api_bp.route("/unassign", methods=["POST"])
@authed_only
@csrf_protect
def api_modules_unassign_challenge():
    disabled = _ensure_modules_enabled()
    if disabled:
        return disabled

    user = get_current_user()
    if not user or getattr(user, "type", None) != "admin":
        return _forbidden_response()

    body = request.get_json(silent=True) or {}
    challenge_id = body.get("challenge_id")
    try:
        challenge_id = int(challenge_id)
    except Exception:
        return jsonify({"success": False, "error": "INVALID_PAYLOAD"}), 400

    module_id = body.get("module_id")
    if module_id in (None, ""):
        ModuleChallenge.query.filter_by(challenge_id=challenge_id).delete()
    else:
        try:
            module_id = int(module_id)
        except Exception:
            return jsonify({"success": False, "error": "INVALID_PAYLOAD"}), 400
        ModuleChallenge.query.filter_by(challenge_id=challenge_id, module_id=module_id).delete()

    db.session.commit()
    return jsonify({"success": True})


@modules_api_bp.route("/challenge/<int:challenge_id>", methods=["GET"])
@authed_only
def api_modules_challenge_mapping(challenge_id: int):
    disabled = _ensure_modules_enabled()
    if disabled:
        return disabled

    user = get_current_user()
    if not user or getattr(user, "type", None) != "admin":
        return _forbidden_response()

    rows = ModuleChallenge.query.filter_by(challenge_id=challenge_id).all()
    module_ids = sorted({row.module_id for row in rows})
    modules = Module.query.filter(Module.id.in_(module_ids)).order_by(Module.name.asc()).all() if module_ids else []

    return jsonify(
        {
            "success": True,
            "data": {
                "challenge_id": challenge_id,
                "module_ids": module_ids,
                "modules": [{"id": module.id, "name": module.name} for module in modules],
                "module_id": (module_ids[0] if module_ids else None),
                "module_name": (modules[0].name if modules else None),
            },
        }
    )


@modules_api_bp.route("/bulk/assign", methods=["POST"])
@authed_only
@csrf_protect
def api_modules_bulk_assign_challenges():
    """Add or unassign module mapping for multiple challenges.

    Payload:
      - challenge_ids: list[int]
      - module_id: int | null | ""  (empty/null -> unassign all mappings)
    """

    disabled = _ensure_modules_enabled()
    if disabled:
        return disabled

    user = get_current_user()
    if not user or getattr(user, "type", None) != "admin":
        return _forbidden_response()

    body = request.get_json(silent=True) or {}
    raw_ids = body.get("challenge_ids")
    raw_module_id = body.get("module_id")

    if not isinstance(raw_ids, list) or not raw_ids:
        return jsonify({"success": False, "error": "INVALID_PAYLOAD"}), 400

    challenge_ids: list[int] = []
    for x in raw_ids:
        try:
            challenge_ids.append(int(x))
        except Exception:
            continue
    # De-dup while preserving order
    challenge_ids = list(dict.fromkeys([cid for cid in challenge_ids if cid > 0]))
    if not challenge_ids:
        return jsonify({"success": False, "error": "INVALID_PAYLOAD"}), 400

    module_id: int | None
    if raw_module_id in (None, ""):
        module_id = None
    else:
        try:
            module_id = int(raw_module_id)
        except Exception:
            return jsonify({"success": False, "error": "INVALID_PAYLOAD"}), 400

    # Validate module existence if assigning
    if module_id is not None and not Module.query.get(module_id):
        return jsonify({"success": False, "error": "MODULE_NOT_FOUND"}), 404

    # Only operate on existing challenges
    existing_ids = {
        cid
        for (cid,) in db.session.query(Challenges.id)
        .filter(Challenges.id.in_(challenge_ids))
        .all()
    }
    if not existing_ids:
        return jsonify({"success": False, "error": "NO_CHALLENGES_FOUND"}), 404

    from .models import ModuleChallenge

    if module_id is None:
        ModuleChallenge.query.filter(ModuleChallenge.challenge_id.in_(list(existing_ids))).delete(
            synchronize_session=False
        )
        db.session.commit()
        return jsonify({"success": True, "data": {"updated": len(existing_ids), "module_id": None}})

    rows = (
        db.session.query(ModuleChallenge.challenge_id)
        .filter(ModuleChallenge.challenge_id.in_(list(existing_ids)))
        .filter(ModuleChallenge.module_id == module_id)
        .all()
    )
    already_linked = {cid for (cid,) in rows}
    for cid in existing_ids:
        if cid in already_linked:
            continue
        db.session.add(ModuleChallenge(challenge_id=cid, module_id=module_id))

    db.session.commit()
    return jsonify({"success": True, "data": {"updated": len(existing_ids), "module_id": module_id}})


@modules_api_bp.route("/<int:module_id>/progress", methods=["GET"])
@authed_only
def api_modules_progress(module_id: int):
    disabled = _ensure_modules_enabled()
    if disabled:
        return disabled

    user = get_current_user()
    module = Module.query.get_or_404(module_id)
    access_error = _module_access_error(module, user)
    if access_error:
        return access_error

    return jsonify({"success": True, "data": module_progress(user, module)})


def _require_admin():
    user = get_current_user()
    if not user or getattr(user, "type", None) != "admin":
        return None, _forbidden_response()
    return user, None


@modules_api_bp.route("/admin/list", methods=["GET"])
@authed_only
def api_admin_modules_list():
    _, err = _require_admin()
    if err:
        return err

    modules = ordered_modules_query().all()
    data = []
    for m in modules:
        data.append({
            "id": m.id,
            "name": m.name,
            "category": m.category,
            "banner_url": m.banner_url,
            "order": m.order,
            "status": m.status.value if hasattr(m.status, "value") else str(m.status),
            "invite_code": m.invite_code,
        })
    return jsonify({"success": True, "data": data})


@modules_api_bp.route("/admin/create", methods=["POST"])
@authed_only
def api_admin_modules_create():
    _, err = _require_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "error": "NAME_REQUIRED"}), 400

    if Module.query.filter(Module.name == name).first():
        return jsonify({"success": False, "error": "MODULE_ALREADY_EXISTS"}), 409

    category_name = (body.get("category") or "").strip() or None
    if category_name:
        existing_cat = ModuleCategory.query.filter_by(name=category_name).first()
        if not existing_cat:
            max_order = db.session.query(db.func.max(ModuleCategory.order)).scalar() or 0
            db.session.add(ModuleCategory(name=category_name, order=int(max_order) + 1))

    status_raw = (body.get("status") or "public").strip()
    try:
        status = ModuleStatus(status_raw)
    except ValueError:
        return jsonify({"success": False, "error": "INVALID_STATUS"}), 400

    order = 0
    if body.get("order") is not None:
        try:
            order = int(body["order"])
        except (ValueError, TypeError):
            pass

    m = Module(
        name=name,
        category=category_name,
        banner_url=(body.get("banner_url") or "").strip() or None,
        order=order,
        status=status,
    )
    ensure_private_invite_code(m)
    db.session.add(m)
    db.session.commit()

    return jsonify({
        "success": True,
        "data": {
            "id": m.id,
            "name": m.name,
            "category": m.category,
            "status": m.status.value,
            "order": m.order,
            "invite_code": m.invite_code,
        },
    }), 201


@modules_api_bp.route("/admin/<int:module_id>", methods=["PATCH"])
@authed_only
def api_admin_modules_update(module_id: int):
    _, err = _require_admin()
    if err:
        return err

    m = Module.query.get_or_404(module_id)
    body = request.get_json(silent=True) or {}

    if "name" in body:
        name = (body["name"] or "").strip()
        if not name:
            return jsonify({"success": False, "error": "NAME_REQUIRED"}), 400
        dup = Module.query.filter(Module.name == name, Module.id != m.id).first()
        if dup:
            return jsonify({"success": False, "error": "MODULE_ALREADY_EXISTS"}), 409
        m.name = name

    if "category" in body:
        category_name = (body["category"] or "").strip() or None
        if category_name:
            existing_cat = ModuleCategory.query.filter_by(name=category_name).first()
            if not existing_cat:
                max_order = db.session.query(db.func.max(ModuleCategory.order)).scalar() or 0
                db.session.add(ModuleCategory(name=category_name, order=int(max_order) + 1))
        m.category = category_name

    if "status" in body:
        try:
            m.status = ModuleStatus((body["status"] or "public").strip())
        except ValueError:
            return jsonify({"success": False, "error": "INVALID_STATUS"}), 400

    if "banner_url" in body:
        m.banner_url = (body["banner_url"] or "").strip() or None

    if "order" in body:
        try:
            m.order = int(body["order"])
        except (ValueError, TypeError):
            pass

    ensure_private_invite_code(m)
    db.session.commit()

    return jsonify({
        "success": True,
        "data": {
            "id": m.id,
            "name": m.name,
            "category": m.category,
            "status": m.status.value,
            "order": m.order,
            "invite_code": m.invite_code,
        },
    })


@modules_api_bp.route("/admin/<int:module_id>", methods=["DELETE"])
@authed_only
def api_admin_modules_delete(module_id: int):
    _, err = _require_admin()
    if err:
        return err

    from .models import ModuleAccess

    m = Module.query.get_or_404(module_id)
    ModuleAccess.query.filter_by(module_id=m.id).delete()
    ModuleChallenge.query.filter_by(module_id=m.id).delete()
    db.session.delete(m)
    db.session.commit()

    return jsonify({"success": True})


@modules_api_bp.route("/admin/categories", methods=["GET"])
@authed_only
def api_admin_categories_list():
    _, err = _require_admin()
    if err:
        return err

    categories = ordered_categories_query().all()
    data = [{"id": c.id, "name": c.name, "order": c.order} for c in categories]
    return jsonify({"success": True, "data": data})


@modules_api_bp.route("/admin/categories", methods=["POST"])
@authed_only
def api_admin_categories_create():
    _, err = _require_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "error": "NAME_REQUIRED"}), 400

    if ModuleCategory.query.filter_by(name=name).first():
        return jsonify({"success": False, "error": "CATEGORY_ALREADY_EXISTS"}), 409

    order = 0
    if body.get("order") is not None:
        try:
            order = int(body["order"])
        except (ValueError, TypeError):
            pass
    else:
        max_order = db.session.query(db.func.max(ModuleCategory.order)).scalar() or 0
        order = int(max_order) + 1

    cat = ModuleCategory(name=name, order=order)
    db.session.add(cat)
    db.session.commit()

    return jsonify({
        "success": True,
        "data": {"id": cat.id, "name": cat.name, "order": cat.order},
    }), 201


@modules_api_bp.route("/admin/categories/<int:category_id>", methods=["DELETE"])
@authed_only
def api_admin_categories_delete(category_id: int):
    _, err = _require_admin()
    if err:
        return err

    cat = ModuleCategory.query.get_or_404(category_id)
    Module.query.filter(Module.category == cat.name).update({"category": None})
    db.session.delete(cat)
    db.session.commit()

    return jsonify({"success": True})
