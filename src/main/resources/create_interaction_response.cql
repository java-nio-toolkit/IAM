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

BEGIN TRANSACTION
    LET interaction_data = (SELECT * FROM integrations.interactions WHERE user_id = :user_id AND application_id = :application_id AND interaction_id = :interaction_id);

    -- Return data directly from table (must come before INSERT)
    SELECT * FROM integrations.interactions WHERE user_id = :user_id AND application_id = :application_id AND interaction_id = :interaction_id;

    IF interaction_data IS NOT NULL THEN
        DELETE FROM integrations.interactions WHERE user_id = :user_id AND application_id = :application_id AND interaction_id = :interaction_id;
        INSERT INTO integrations.responses (interaction_id, user_id, owner_id, application_id, permissions)
        VALUES (:interaction_id, :user_id, :owner_id, :application_id, :permissions);
        INSERT INTO users.entitlements (user_id, application_id, owner_id, flags, permissions, updated_at)
        VALUES (:user_id, :application_id, :owner_id, :flags, :permissions, :updated_at);
    END IF
COMMIT TRANSACTION;
