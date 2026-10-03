/*
 * Copyright 2026 Ada Morgan, John Regan and the JACT contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

INSERT INTO integrations.interactions (user_id, application_id, interaction_id, expiry, permissions, redirect_uri, nonce, finish, method_hash, uri, hash, access_raw, label)
VALUES (:user_id, :application_id, :interaction_id, :expiry, :permissions, :redirect_uri, :nonce, :finish, :method_hash, :uri, :hash, :access_raw, :label);
