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
    LET access_data = (SELECT * FROM users.public_keys WHERE user_id = :user_id AND thumbprint = :thumbprint);
    LET application_data = (SELECT * FROM integrations.public_keys WHERE user_id = :user_id AND application_id = :application_id AND thumbprint = :thumbprint);

    -- Return data directly from table (must come before INSERT)
    SELECT * FROM integrations.public_keys WHERE user_id = :user_id AND application_id = :application_id AND thumbprint = :thumbprint;

    IF access_data IS NULL AND application_data IS NULL THEN
        INSERT INTO users.public_keys (user_id, kid, alg, kty, usage, thumbprint, public_key)
        VALUES (:user_id, :kid, :alg, :kty, :usage, :thumbprint, :public_key);
        INSERT INTO integrations.public_keys (user_id, application_id, thumbprint)
        VALUES (:user_id, :application_id, :thumbprint);
    END IF
COMMIT TRANSACTION;
