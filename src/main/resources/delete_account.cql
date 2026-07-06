/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
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
    LET account_data = (SELECT * FROM users.accounts WHERE user_id = :user_id);

    -- Return data directly from table (must come before INSERT)
    SELECT * FROM users.accounts WHERE user_id = :user_id;

    IF account_data IS NOT NULL THEN
        DELETE FROM users.sessions WHERE user_id = :user_id;
        DELETE FROM users.accounts WHERE user_id = :user_id;
    END IF
COMMIT TRANSACTION;
