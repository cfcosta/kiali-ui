import { createAction } from 'typesafe-actions';
import * as API from '../services/Api';
import { Token } from '../store/Store';
import { HTTP_CODES } from '../types/Common';
import { HelpDropdownActions } from './HelpDropdownActions';
import { GrafanaActions } from './GrafanaActions';
import { config } from '../config';
import _ from 'lodash';

export enum LoginActionKeys {
  LOGIN_REQUEST = 'LOGIN_REQUEST',
  LOGIN_EXTEND = 'LOGIN_EXTEND',
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  LOGOUT_SUCCESS = 'LOGOUT_SUCCESS',
  OAUTH_STATUS = 'OAUTH_STATUS'
}

// synchronous action creators
export const LoginActions = {
  oauthStatus: createAction(LoginActionKeys.OAUTH_STATUS, (enabled: boolean, authorizationEndpoint: string) => ({
    type: LoginActionKeys.OAUTH_STATUS,
    isLoading: false,
    enabled: enabled,
    authorizationEndpoint: authorizationEndpoint
  })),
  loginRequest: createAction(LoginActionKeys.LOGIN_REQUEST),
  loginExtend: createAction(LoginActionKeys.LOGIN_EXTEND, (token: Token, username: string, currentTimeOut: number) => ({
    type: LoginActionKeys.LOGIN_EXTEND,
    token: token,
    username: username,
    sessionTimeOut: currentTimeOut + config().session.extendedSessionTimeOut
  })),
  loginSuccess: createAction(
    LoginActionKeys.LOGIN_SUCCESS,
    (token: Token, username: string, currentTimeOut?: number) => ({
      type: LoginActionKeys.LOGIN_SUCCESS,
      token: token,
      username: username,
      logged: true,
      sessionTimeOut: currentTimeOut || new Date().getTime() + config().session.sessionTimeOut
    })
  ),
  loginFailure: createAction(LoginActionKeys.LOGIN_FAILURE, (error: any) => ({
    type: LoginActionKeys.LOGIN_FAILURE,
    error: error
  })),
  logoutSuccess: createAction(LoginActionKeys.LOGOUT_SUCCESS, () => ({
    type: LoginActionKeys.LOGOUT_SUCCESS,
    token: undefined,
    username: undefined,
    logged: false,
    oauth: undefined
  })),
  extendSession: () => {
    return (dispatch, getState) => {
      const actualState = getState() || {};
      dispatch(
        LoginActions.loginExtend(
          actualState.authentication.token,
          actualState.authentication.username,
          actualState.authentication.sessionTimeOut
        )
      );
    };
  },
  checkCredentials: () => {
    return (dispatch, getState) => {
      const actualState = getState() || {};

      /** Check if there is a token in session */
      if (actualState['authentication']['token'] === undefined) {
        if (!actualState['oauth']) {
          dispatch(LoginActions.checkOauthAndRedirect());
        } else {
          /** Logout user */
          dispatch(LoginActions.logoutSuccess());
          dispatch(LoginActions.checkOauthAndRedirect());
        }
      } else {
        /** Check the session timeout */
        if (new Date().getTime() > getState().authentication.sessionTimeOut) {
          dispatch(LoginActions.logoutSuccess());
        } else {
          /** Get the token storage in redux-store */
          const token = getState().authentication.token.token;
          /** Check if the token is valid */
          const auth = `Bearer ${token}`;
          API.getNamespaces(auth).then(
            status => {
              /** Login success */
              dispatch(
                LoginActions.loginSuccess(
                  actualState['authentication']['token'],
                  actualState['authentication']['username'],
                  actualState['authentication']['sessionTimeOut']
                )
              );
              dispatch(HelpDropdownActions.refresh());
              dispatch(GrafanaActions.getInfo(auth));
            },
            error => {
              /** Logout user */
              if (error.response && error.response.status === HTTP_CODES.UNAUTHORIZED) {
                dispatch(LoginActions.logoutSuccess());
              }
            }
          );
        }
      }
    };
  },
  checkOauthAndRedirect: () => {
    return (dispatch, getState) => {
      const hashParams: any = window.location.hash
        .split('&')
        .map(v => v.split('='))
        .reduce((accum, [key, value]) => ({ ...accum, [_.camelCase(key)]: decodeURI(value) }), {});

      if (hashParams.accessToken) {
        window.location.hash = '';

        // Here we get the user info, namely it's username so we can show on the bar.
        // If that does not happen, then we logout the user again, since the
        // only situation where that should happen is when either the token is
        // not valid anymore or the server is not available. Either way the
        // user should not be able to do any action in those situations.
        API.getUserInfo()
          .then(user => {
            dispatch(LoginActions.loginSuccess(hashParams.accessToken, user.data.username));
            dispatch(HelpDropdownActions.refresh());
          })
          .catch(() => dispatch(LoginActions.logoutSuccess()));
      } else {
        if (getState().authentication && !getState().authentication!.enabled) {
          return;
        }

        API.getOAuthStatus()
          .then(status => {
            dispatch(LoginActions.oauthStatus(true, status.data.authorizationEndpoint));
            window.location.href = status.data.authorizationEndpoint;
          })
          .catch(() => dispatch(LoginActions.oauthStatus(false, '')));
      }
    };
  },
  // action creator that performs the async request
  authenticate: (username: string, password: string) => {
    return dispatch => {
      dispatch(LoginActions.loginRequest());
      API.login(username, password).then(
        token => {
          dispatch(LoginActions.loginSuccess(token['data'], username));
          dispatch(HelpDropdownActions.refresh());
        },
        error => {
          dispatch(LoginActions.loginFailure(error));
        }
      );
    };
  }
};
