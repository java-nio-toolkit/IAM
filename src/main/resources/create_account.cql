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
    LET session_data = (SELECT * FROM users.sessions WHERE user_id = :user_id AND session_id = :session_id);

    -- Return data directly from table (must come before INSERT)
    SELECT * FROM users.sessions WHERE user_id = :user_id AND session_id = :session_id;

    IF session_data IS NULL THEN
        INSERT INTO users.sessions (user_id, session_id, flags, user_agent, alg, kid, kty, usage, public_key, thumbprint)
        VALUES (:user_id, :session_id, :flags, :user_agent, :alg, :kid, :kty, :usage, :public_key, :thumbprint);
        INSERT INTO users.accounts (user_id, username, flags)
        VALUES (:user_id, :username, :flags);
    END IF
COMMIT TRANSACTION;
