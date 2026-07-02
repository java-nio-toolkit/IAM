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

CREATE KEYSPACE IF NOT EXISTS users WITH replication =
    {
        'class': 'SimpleStrategy',
        'replication_factor': 1
        };

CREATE TABLE if not exists users.public_keys
(
    kid        uuid PRIMARY KEY,
    public_key blob,
    alg        text,
    created_at timestamp,
    expires_at timestamp
);

create table if not exists users.accounts
(
    user_id  uuid primary key,
    flags    int,
    username text
) WITH transactional_mode = 'full';

create table if not exists users.sessions
(
    user_id    uuid,
    session_id uuid,
    flags      int,
    user_agent text,
    alg        text,
    kid        text,
    kty        text,
    usage      text,
    thumbprint text,
    public_key blob,
    primary key (user_id, session_id)
) WITH transactional_mode = 'full';


