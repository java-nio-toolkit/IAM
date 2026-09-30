/*
 * Copyright 2025 Ada Morgan, John Regan and the JNT contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.api.requests;

import com.github.adamorgan.jnt.api.requests.Route;

import static com.github.adamorgan.jnt.api.requests.Method.*;

public class Routes
{
    public static class Applications
    {
        public static final Route CREATE_APPLICATION = new Route(POST, "applications");
        public static final Route CREATE_APPLICATION_INTERACTION = new Route(POST, "users/{user_id}/applications/{application_id}/interactions", true);
        public static final Route ACCEPT_APPLICATION_INTERACTION = new Route(PATCH, "users/{user_id}/applications/{application_id}/interactions/{interaction_id}");
        public static final Route EXECUTE_APPLICATION_INTERACTION = new Route(POST, "applications/{application_id}/interactions/{interaction_id}", true);
        public static final Route GET_SELF_APPLICATIONS = new Route(GET, "applications");
        public static final Route GET_SELF_APPLICATION = new Route(GET, "applications/{application_id}");
        public static final Route GET_ENTITLEMENTS = new Route(GET, "users/@me/applications");
        public static final Route GET_ENTITLEMENT = new Route(GET, "users/@me/applications/{application_id}");
        public static final Route EDIT_APPLICATION = new Route(PATCH, "applications/{application_id}");
        public static final Route EDIT_ENTITLEMENT = new Route(PATCH, "users/@me/applications/{application_id}");
        public static final Route UPDATE_ENTITLEMENT_ACCESS = new Route(PUT, "users/@me/applications/{application_id}", true);
        public static final Route DELETE_APPLICATION = new Route(DELETE, "applications/{application_id}");
        public static final Route DELETE_ENTITLEMENT = new Route(DELETE, "users/@me/applications/{application_id}");
    }

    public static class Self
    {
        public static final Route GET_SELF = new Route(GET, "users/@me");
        public static final Route CREATE_SELF = new Route(POST, "users/@me", true);
        public static final Route MODIFY_SELF = new Route(PATCH, "users/@me");
        public static final Route DELETE_SELF = new Route(DELETE, "users/@me");
    }

    public static class Users
    {
        public static final Route GET_USER = new Route(GET, "users/{user_id}");
    }

    public static class Session
    {
        public static final Route GET_SESSIONS = new Route(GET, "sessions");
        public static final Route GET_SESSION = new Route(GET, "sessions/{session_id}");
        public static final Route ADD_SESSION = new Route(POST, "sessions");
        public static final Route EDIT_SESSION = new Route(PATCH, "sessions/{session_id}");
        public static final Route UPDATE_SESSION_ACCESS = new Route(PUT, "sessions/{session_id}", true);
        public static final Route REMOVE_SESSION = new Route(DELETE, "sessions/{session_id}");
        public static final Route REMOVE_ALL_SESSIONS = new Route(DELETE, "sessions");
    }

    public static class Webhooks
    {
        public static final Route CREATE_WEBHOOK = new Route(POST, "webhooks");
        public static final Route GET_WEBHOOKS = new Route(GET, "webhooks");
        public static final Route GET_WEBHOOK = new Route(GET, "webhooks/{webhook_id}");
        public static final Route MODIFY_WEBHOOK = new Route(PATCH, "webhooks/{webhook_id}");
        public static final Route DELETE_WEBHOOK = new Route(DELETE, "webhooks/{webhook_id}");
    }
}
