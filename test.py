# =========================================
# 1️⃣ ENUMS & TYPES
# =========================================

from enum import Enum
from dataclasses import dataclass
from typing import List, Optional, Set


class IdentityType(Enum):
    """Type d'identité détecté."""
    SERVER_TO_SERVER = "SERVER_TO_SERVER"  # mTLS
    ANALYST_TOKEN = "ANALYST_TOKEN"  # Bearer token
    USER_SSO = "USER_SSO"  # Session cookie
    NONE = "NONE"  # Pas d'auth


class AccessLevel(Enum):
    """Niveau d'accès."""
    UNRESTRICTED = "UNRESTRICTED"  # Accès à toutes les apps
    RESTRICTED = "RESTRICTED"  # Accès limité à certaines apps
    DENIED = "DENIED"  # Accès refusé


@dataclass
class AuthContext:
    """Contexte d'autorisation injecté dans request."""
    identity_type: IdentityType
    user_id: Optional[str] = None
    app_names: Optional[List[str]] = None  # Pour TOKEN
    mtls_cn: Optional[str] = None  # Pour mTLS
    access_level: AccessLevel = AccessLevel.DENIED


# =========================================
# 2️⃣ HELPERS D'AUTHENTIFICATION
# =========================================

import jwt
import ssl
from flask import request, g
from functools import wraps
from config import Config


class AuthenticationError(Exception):
    """Erreur d'authentification."""
    pass


class AuthorizationError(Exception):
    """Erreur d'autorisation."""
    pass


def extract_mtls_cn() -> Optional[str]:
    """
    Extrait le CN du certificat client mTLS.

    Fonctionne avec:
    - SSL/TLS proxy (nginx, reverse proxy)
    - WSGI server (gunicorn avec --ca-certs)
    """
    # Via header HTTP (nginx proxy)
    if 'X-SSL-Client-S-DN-CN' in request.headers:
        return request.headers.get('X-SSL-Client-S-DN-CN')

    # Via environment WSGI (gunicorn direct)
    if 'SSL_CLIENT_S_DN_CN' in request.environ:
        return request.environ.get('SSL_CLIENT_S_DN_CN')

    # Via environment brut
    if 'SSL_CLIENT_S_DN' in request.environ:
        dn = request.environ.get('SSL_CLIENT_S_DN')
        # Parse DN: "CN=appA,O=Company,C=FR"
        for part in dn.split(','):
            if part.strip().startswith('CN='):
                return part.strip()[3:]

    return None


def extract_bearer_token() -> Optional[str]:
    """Extrait le token JWT du header Authorization."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    return auth_header[7:]


def verify_jwt_token(token: str) -> dict:
    """
    Vérifie et décode le JWT.

    Raises: AuthenticationError si invalide
    """
    try:
        decoded = jwt.decode(
            token,
            Config.SECRET_KEY,
            algorithms=['HS256']
        )
        return decoded
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token expired")
    except jwt.InvalidTokenError as e:
        raise AuthenticationError(f"Invalid token: {str(e)}")


def verify_session_cookie() -> Optional[str]:
    """
    Vérifie la session SSO.

    Returns: user_id si session valide, None sinon
    """
    session_token = request.cookies.get('session_token')
    if not session_token:
        return None

    session = ApplicationSession.query.filter_by(
        session_token=session_token,
        is_active=True
    ).first()

    if not session:
        return None

    if session.expires_at < datetime.utcnow():
        return None

    # Mettre à jour last_activity
    session.last_activity = datetime.utcnow()
    db.session.commit()

    return session.user_id


def get_app_names_from_token(app_names_raw: str) -> List[str]:
    """Parse la liste d'apps du token."""
    if isinstance(app_names_raw, list):
        return app_names_raw
    if isinstance(app_names_raw, str):
        return [a.strip() for a in app_names_raw.split(',')]
    return []


# =========================================
# 3️⃣ IDENTITY DETECTION - PIPELINE
# =========================================

def detect_identity() -> AuthContext:
    """
    Pipeline d'identification (ordre critique).

    Priorité:
    1. mTLS → SERVER_TO_SERVER
    2. Bearer token → ANALYST_TOKEN
    3. Session cookie → USER_SSO
    4. Rien → NONE (401)
    """

    # 1️⃣ Vérifier mTLS (server-to-server)
    mtls_cn = extract_mtls_cn()
    if mtls_cn:
        return AuthContext(
            identity_type=IdentityType.SERVER_TO_SERVER,
            mtls_cn=mtls_cn,
            access_level=AccessLevel.RESTRICTED
        )

    # 2️⃣ Vérifier Bearer token
    token = extract_bearer_token()
    if token:
        try:
            decoded = verify_jwt_token(token)

            # Vérifier la structure du token
            if decoded.get('type') != 'ANALYST':
                raise AuthenticationError("Invalid token type")

            app_names = get_app_names_from_token(
                decoded.get('app_names', [])
            )

            return AuthContext(
                identity_type=IdentityType.ANALYST_TOKEN,
                user_id=decoded.get('token_name'),
                app_names=app_names,
                access_level=AccessLevel.RESTRICTED
            )
        except AuthenticationError:
            raise

    # 3️⃣ Vérifier session SSO
    user_id = verify_session_cookie()
    if user_id:
        return AuthContext(
            identity_type=IdentityType.USER_SSO,
            user_id=user_id,
            access_level=AccessLevel.RESTRICTED
        )

    # 4️⃣ Aucune auth détectée
    return AuthContext(
        identity_type=IdentityType.NONE,
        access_level=AccessLevel.DENIED
    )


# =========================================
# 4️⃣ AUTORISATION - VÉRIFICATION D'ACCÈS
# =========================================

def authorize_app_access(
        auth_context: AuthContext,
        requested_apps: Optional[List[str]] = None
) -> None:
    """
    Vérifie l'accès aux applications demandées.

    Raises: AuthorizationError si non autorisé
    """

    # ❌ Pas d'identité du tout
    if auth_context.identity_type == IdentityType.NONE:
        raise AuthenticationError("No valid authentication")

    # ✅ USER_SSO: ne peut PAS utiliser app_ids
    if auth_context.identity_type == IdentityType.USER_SSO:
        if requested_apps:
            raise AuthorizationError(
                "Users cannot access app listing features. "
                "This endpoint is reserved for analysts."
            )
        return

    # ✅ ANALYST_TOKEN: apps demandées ⊆ apps du token
    if auth_context.identity_type == IdentityType.ANALYST_TOKEN:
        if not requested_apps:
            # Token analyst sans apps demandées = OK
            return

        token_apps = set(auth_context.app_names or [])
        requested_set = set(requested_apps)

        unauthorized = requested_set - token_apps
        if unauthorized:
            raise AuthorizationError(
                f"Token does not grant access to: {', '.join(unauthorized)}. "
                f"Available: {', '.join(token_apps)}"
            )
        return

    # ✅ SERVER_TO_SERVER (mTLS): CN = seule app accessible
    if auth_context.identity_type == IdentityType.SERVER_TO_SERVER:
        if not requested_apps:
            raise AuthorizationError(
                "Server-to-server requires explicit app specification"
            )

        if len(requested_apps) != 1 or requested_apps[0] != auth_context.mtls_cn:
            raise AuthorizationError(
                f"Certificate CN '{auth_context.mtls_cn}' "
                f"can only access itself, not {requested_apps}"
            )
        return


# =========================================
# 5️⃣ DÉCORATEURS PRINCIPAUX
# =========================================

def authenticate_request(f):
    """
    Décorateur: détecte l'identité et la stocke dans g.auth.

    S'exécute AVANT authorize_request.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            auth_context = detect_identity()
            g.auth = auth_context
        except AuthenticationError as e:
            return jsonify({'error': str(e)}), 401

        return f(*args, **kwargs)

    return wrapper


def authorize_request(app_param: Optional[str] = None):
    """
    Décorateur: vérifie que l'identité a le droit d'accès.

    :param app_param: Nom du paramètre contenant les app_ids
                      (json, query, kwargs)

    Utilisation:
        @authorize_request(app_param="app_ids")
    """

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Récupérer le contexte auth (set par @authenticate_request)
            auth_context = g.get('auth')
            if not auth_context:
                return jsonify({'error': 'Authentication required'}), 401

            # Extraire les app_ids demandés
            requested_apps = None
            if app_param:
                # Priorité: JSON → Query → kwargs
                if request.json:
                    requested_apps = request.json.get(app_param)
                if not requested_apps:
                    requested_apps = request.args.get(app_param)
                if not requested_apps:
                    requested_apps = kwargs.get(app_param)

                # Parser en liste
                if isinstance(requested_apps, str):
                    requested_apps = [
                        a.strip() for a in requested_apps.split(',')
                        if a.strip()
                    ]
                elif isinstance(requested_apps, list):
                    requested_apps = [
                        str(a).strip() for a in requested_apps
                        if a
                    ]

            # Vérifier l'accès
            try:
                authorize_app_access(auth_context, requested_apps)
                g.requested_apps = requested_apps
            except (AuthenticationError, AuthorizationError) as e:
                status = 401 if isinstance(e, AuthenticationError) else 403
                return jsonify({'error': str(e)}), status

            return f(*args, **kwargs)

        return wrapper

    return decorator


# =========================================
# 6️⃣ ROUTE PROTÉGÉE - EXEMPLE RÉÉCRIT
# =========================================

@form_container_bp.route("/form-containers", methods=["GET"])
@authenticate_request
@authorize_request(app_param="app_ids")
def get_form_containers():
    """
    Récupère les form-containers filtrés par app_ids.

    Accès:
    - USER: ❌ 403 (utilise app_ids)
    - ANALYST_TOKEN: ✅ Si apps ⊆ token.app_names
    - SERVER_TO_SERVER: ✅ Si app_ids = CN du certificat

    Query params:
    - app_ids (str): Comma-separated app IDs (REQUIRED)
    - page (int): Page number (default: 1)
    - limit (int): Items per page (default: 50)
    - status (str): Filter by form status
    - title (str): Search by title
    - user_email (str): Filter by email
    - dateRange (str): ISO date range "YYYY-MM-DD,YYYY-MM-DD"
    """

    user_id = getattr(g.auth, 'user_id', None)
    requested_apps = g.get('requested_apps', [])

    # ✅ Logique métier inchangée
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = (page - 1) * limit

    if page < 1 or limit < 1:
        return jsonify({'error': 'Invalid pagination parameters'}), 400

    # Filtres
    status = request.args.get("status")
    title = request.args.get("title", "").strip()
    user_email = request.args.get("user_email", "").strip()
    campaign_ids = request.args.get("campaign_ids", "")
    date_range = request.args.get("dateRange", "")

    query = FormContainer.query.filter(
        FormContainer.app_id.in_(requested_apps)
    )

    if status:
        if status in ("reminder", "escalate"):
            query = query.filter(
                FormContainer.forms.any(
                    and_(
                        Form.workflow_step == status,
                        Form.status == "open"
                    )
                )
            )
        else:
            query = query.filter(
                FormContainer.forms.any(Form.status == status)
            )

    if title:
        query = query.filter(
            FormContainer.title.ilike(f"%{title}%")
        )

    if user_email:
        query = query.filter(
            FormContainer.user_email.ilike(f"%{user_email}%")
        )

    if campaign_ids:
        campaign_list = campaign_ids.split(',')
        query = query.filter(
            or_(*[
                FormContainer.campaign_id.ilike(f"%{c}%")
                for c in campaign_list
            ])
        )

    if date_range:
        try:
            start_date, end_date = date_range.split(",")
            start_date = datetime.fromisoformat(start_date.replace("Z", ""))
            end_date = datetime.fromisoformat(end_date.replace("Z", ""))
            query = query.filter(
                FormContainer.created_at.between(start_date, end_date)
            )
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400

    sort_order = request.args.get("sort", "desc").lower()
    if sort_order == "asc":
        query = query.order_by(FormContainer.created_at.asc())
    else:
        query = query.order_by(FormContainer.created_at.desc())

    total = query.count()
    paginated_query = query.limit(limit).offset(offset)
    results = paginated_query.all()
    schema = FormContainerListSchema(many=True)

    return jsonify({
        "total": total,
        "page": page,
        "page_size": limit,
        "accessed_by": g.auth.identity_type.value,
        "form_containers": schema.dump(results)
    }), 200


# =========================================
# 7️⃣ ROUTE SIMPLE (sans app_ids) - USER OK
# =========================================

@form_container_bp.route("/form-containers/<string:access_token>", methods=["GET"])
@authenticate_request
@authorize_request()  # Pas d'app_param → USER ok
def get_form_container_by_token(access_token):
    """
    Récupère UN form-container par access_token.

    Accès:
    - USER: ✅ OK (pas d'app_ids)
    - ANALYST_TOKEN: ✅ OK
    - SERVER_TO_SERVER: ✅ OK
    """
    form_container = FormContainer.query.filter_by(
        access_token=access_token
    ).first_or_404()

    schema = FormContainerDetailSchema(session=db.session)
    return jsonify(schema.dump(form_container)), 200