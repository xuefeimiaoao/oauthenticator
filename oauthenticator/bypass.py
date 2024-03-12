import base64
import json

from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from tornado import web
from traitlets import Unicode, default, Bool, Set

from oauthenticator import OAuthenticator


class BypassAuthenticateHandler(BaseHandler):
    """
    Provides a GET web request handler for /hub/tmplogin, as registered by
    TmpAuthenticator's override of Authenticator.get_handlers.

    JupyterHub will redirect here if it doesn't recognize a user via a cookie,
    but users can also visit /hub/tmplogin explicitly to get setup with a new
    user.
    """

    async def get(self):
        """
        Authenticate as a new random user no matter what.

        This GET request handler mimics parts of what's done by JupyterHub's
        LoginHandler when a user isn't recognized: to first call
        BaseHandler.login_user and then redirect the user onwards. The
        difference is that here users always login as a new user.

        By overwriting any previous user's identifying cookie, it acts as a
        combination of a logout and login handler.

        JupyterHub's LoginHandler ref: https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/handlers/login.py#L129-L138
        """
        # Login as a new user, without checking if we were already logged in
        #
        user = await self.login_user(None)

        # Set or overwrite the login cookie to recognize the new user.
        #
        # login_user calls set_login_cookie(user), that sets a login cookie for
        # the user via set_hub_cookie(user), but only if it doesn't recognize a
        # user from an pre-existing login cookie. Due to that, we
        # unconditionally call self.set_hub_cookie(user) here.
        #
        # BaseHandler.login_user:                   https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/handlers/base.py#L823-L843
        # - BaseHandler.authenticate:               https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/handlers/base.py#L643-L644
        #   - Authenticator.get_authenticated_user: https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/auth.py#L472-L534
        # - BaseHandler.auth_to_user:               https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/handlers/base.py#L774-L821
        # - BaseHandler.set_login_cookie:           https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/handlers/base.py#L627-L628
        #   - BaseHandler.set_session_cookie:       https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/handlers/base.py#L601-L613
        #   - BaseHandler.set_hub_cookie:           https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/handlers/base.py#L623-L625
        #
        self.set_hub_cookie(user)

        # Login complete, redirect the user.
        #
        # BaseHandler.get_next_url ref: https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/handlers/base.py#L646-L653
        #
        next_url = self.get_next_url(user)
        self.redirect(next_url)


class BypassAuthenticator(OAuthenticator):
    """
    When JupyterHub is configured to use this authenticator, visiting the home
    page immediately logs the user in if they are
    already logged in and token is left in header, and spawns a server for them.
    """

    acess_token_key_in_header = Unicode(
        default_value="Authorization",
        help="""
        Key of Access token in headers.
        """
    )

    acess_token_key_in_cookie = Unicode(
        default_value="token",
        help="""
        Key of Access token in cookie.
        """
    )

    manage_groups = Bool(
        True,
        config=True,
        help="""Let authenticator manage user groups

        If True, Authenticator.authenticate and/or .refresh_user
        may return a list of group names in the 'groups' field,
        which will be assigned to the user.

        All group-assignment APIs are disabled if this is True.
        """,
    )

    usergroup_claim = Unicode(
        'owner',
        config=True,
        help="""
        When `userdata_url` returns a json response, the username will be taken
        from this key.

        Can be a string key name or a callable that accepts the returned
        userdata json (as a dict) and returns the username.  The callable is
        useful e.g. for extracting the username from a nested object in the
        response or doing other post processing.

        What keys are available will depend on the scopes requested and the
        authenticator used.
        """,
    )

    allow_all = Bool(
        True,
        config=True,
        help="""
        Allow all authenticated users to login.

        Overrides all other `allow` configuration.

        .. versionadded:: 16.0
        """,
    )

    @default("auto_login")
    def _auto_login_default(self):
        """
        The Authenticator base class' config auto_login defaults to False, but
        we change that default to True in TmpAuthenticator. This makes users
        automatically get logged in when they hit the hub's home page, without
        requiring them to click a 'login' button.

        JupyterHub admins can still opt back to present the /hub/login page with
        the login button like this:

            c.TmpAuthenticator.auto_login = False
        """
        return True

    login_service = Unicode(
        "Automatic Temporary Credentials",
        help="""
        Text to be shown with the 'Sign in with ...' button, when auto_login is
        False.

        The Authenticator base class' login_service isn't tagged as a
        configurable traitlet, so we redefine it to allow it to be configurable
        like this:

            c.TmpAuthenticator.login_service = "your inherent worth as a human being"
        """,
    ).tag(config=True)

    def check_allowed(self, username, authentication=None):
        """Check if a username is allowed to authenticate based on configuration

        Return True if username is allowed, False otherwise.
        No allowed_users set means any username is allowed.

        Names are normalized *before* being checked against the allowed set.

        .. versionchanged:: 1.0
            Signature updated to accept authentication data and any future changes

        .. versionchanged:: 1.2
            Renamed check_whitelist to check_allowed
        """
        return True

    async def get_token_info(self, handler, params=None):
        """
        Returns:
            the JSON response to the `token_url` the request.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
        if self.acess_token_key_in_header == 'Authorization':
            self.log.info(f"debug request: {str(handler.request)}")
            self.log.info(f"debug headers: {str(handler.request.headers)}")

            authorization = handler.request.headers[self.acess_token_key_in_header]
            if len(authorization.split('Bearer')) == 2:
                access_token = authorization.split('Bearer')[1]
            else:
                raise ValueError("Support Bearer token only!")
        elif self.acess_token_key_in_header == 'Cookie':
            access_token = handler.get_cookie(self.acess_token_key_in_cookie)
        else:
            access_token = handler.request.headers[self.acess_token_key_in_header]
        token_info = {'access_token': access_token,
                      'scope': 'servers users tokens groups access:servers'}

        if "access_token" not in token_info:
            raise web.HTTPError(500, f"Bad response: {token_info}")

        return token_info

    async def token_to_user(self, token_info):
        """
        Determines who the logged-in user by sending a "GET" request to
        :data:`oauthenticator.OAuthenticator.userdata_url` using the `access_token`.

        If :data:`oauthenticator.OAuthenticator.userdata_from_id_token` is set then
        extracts the corresponding info from an `id_token` instead.

        Args:
            token_info: the dictionary returned by the token request (exchanging the OAuth code for an Access Token)

        Returns:
            the JSON response to the `userdata_url` request.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """
        access_token = token_info["access_token"]

        # parse access_token
        # Decode the token to get the payload (second part of the token)
        chunks = access_token.split('.')
        if len(chunks) != 3:
            raise ValueError(f"Invalid access token: {access_token}")

        body = base64.urlsafe_b64decode(chunks[1] + "==").decode('utf-8')  # Adjust base64 padding as necessary
        if not body:
            raise ValueError("Invalid token")

        return json.loads(body)

        # You may want to verify token signature and expiration here
        # This is a simplified example that skips verification for simplicity

        # return await self.httpfetch(
        #     url,
        #     "Fetching user info...",
        #     method="GET",
        #     headers=self.build_userdata_request_headers(access_token, token_type),
        #     validate_cert=self.validate_server_cert,
        # )

    def user_info_to_groups(self, user_info):
        """
        Gets the self.username_claim key's value from the user_info dictionary.

        Should be overridden by the authenticators for which the hub username cannot
        be extracted this way and needs extra processing.

        Args:
            user_info: the dictionary returned by the userdata request

        Returns:
            user_info["self.username_claim"] or raises an error if such value isn't found.

        Called by the :meth:`oauthenticator.OAuthenticator.authenticate`
        """

        if callable(self.usergroup_claim):
            group = self.usergroup_claim(user_info)
        else:
            group = user_info.get(self.usergroup_claim, None)
        if not group:
            message = (f"No {self.usergroup_claim} found in {user_info}",)
            self.log.error(message)
            raise ValueError(message)
        if not isinstance(group, (set, list, tuple)):
            return set([group])
        else:
            return group

    async def authenticate(self, handler, data=None, **kwargs):
        """
        A JupyterHub Authenticator's authenticate method's job is:

        - return None if the user isn't successfully authenticated
        - return a dictionary if authentication is successful with name, admin
          (optional), and auth_state (optional)

        Subclasses should not override this method.

        ref: https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html#authenticator-authenticate-method
        ref: https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/auth.py#L581-L611
        """
        token_info = await self.get_token_info(handler)
        # use the access_token to get userdata info
        user_info = await self.token_to_user(token_info)
        # extract the username out of the user_info dict and normalize it
        username = self.user_info_to_username(user_info)
        username = self.normalize_username(username)
        groups = self.user_info_to_groups(user_info)
        self.log.info(f"Authenticate username: {username}, groups: {groups}")

        # check if there any refresh_token in the token_info dict
        refresh_token = token_info.get("refresh_token", None)
        if self.enable_auth_state and not refresh_token:
            self.log.debug(
                "Refresh token was empty, will try to pull refresh_token from previous auth_state"
            )
            refresh_token = await self.get_prev_refresh_token(handler, username)
            if refresh_token:
                token_info["refresh_token"] = refresh_token
        # build the auth model to be read if authentication goes right
        auth_model = {
            "name": username,
            "admin": True if username in self.admin_users else None,
            "groups": groups,
            "auth_state": self.build_auth_state_dict(token_info, user_info),
        }
        self.log.info(f"Authenticate auth_model: {auth_model}")

        # update the auth_model with info to later authorize the user in
        # check_allowed, such as admin status and group memberships
        return await self.update_auth_model(auth_model)

    def get_handlers(self, app):
        """
        Registers a dedicated endpoint and web request handler for logging in
        with BypassAuthenticateHandler. This is needed as /hub/login is reserved
        for redirecting to what's returned by login_url.

        ref: https://github.com/jupyterhub/jupyterhub/pull/1066
        """
        return [("/bypass_login", BypassAuthenticateHandler)]

    def login_url(self, base_url):
        """
        login_url is overridden as intended for Authenticator subclasses that
        provides a custom login handler (for /hub/tmplogin).

        JupyterHub redirects users to this destination from /hub/login if
        auto_login is set, or if its not set and users press the "Sign in ..."
        button.

        ref: https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/auth.py#L708-L723
        ref: https://github.com/jupyterhub/jupyterhub/blob/4.0.0/jupyterhub/handlers/login.py#L118-L147
        """
        return url_path_join(base_url, "bypass_login")