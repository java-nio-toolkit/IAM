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


CREATE KEYSPACE IF NOT EXISTS global WITH replication =
    {
        'class': 'SimpleStrategy',
        'replication_factor': 1
        };

CREATE KEYSPACE IF NOT EXISTS users WITH replication =
    {
        'class': 'SimpleStrategy',
        'replication_factor': 1
        };

CREATE KEYSPACE IF NOT EXISTS integrations WITH replication =
    {
        'class': 'SimpleStrategy',
        'replication_factor': 1
        };

DROP TABLE IF EXISTS global.public_keys;
DROP TABLE IF EXISTS users.accounts;
DROP TABLE IF EXISTS users.permissions;
DROP TABLE IF EXISTS users.sessions;
DROP TABLE IF EXISTS users.public_keys;
DROP TABLE IF EXISTS integrations.public_keys;
DROP TABLE IF EXISTS integrations.applications;

CREATE TABLE if not exists global.public_keys
(
    kid        text,
    alg        text,
    kty        text,
    usage      text,
    thumbprint text,
    public_key blob,
    primary key (thumbprint)
) WITH transactional_mode = 'full';

CREATE TABLE if not exists users.public_keys
(
    user_id    UUID,
    kid        text,
    alg        text,
    kty        text,
    usage      text,
    thumbprint text,
    public_key blob,
    primary key ((user_id), thumbprint)
) WITH transactional_mode = 'full';

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
    thumbprint text,
    primary key ((user_id), session_id)
) WITH transactional_mode = 'full';

create table if not exists users.permissions
(
    user_id        uuid,
    application_id uuid,
    permissions    int,
    created_at     timestamp,
    updated_at     timestamp,
    PRIMARY KEY ((user_id), application_id)
) WITH transactional_mode = 'full';

create table if not exists integrations.applications
(
    user_id        uuid,
    application_id uuid,
    name           text,
    description    text,
    flags          int,
    redirect_uris  list<text>,
    primary key ((user_id), application_id)
) WITH transactional_mode = 'full';

CREATE TABLE if not exists integrations.public_keys
(
    user_id        UUID,
    application_id UUID,
    thumbprint     text,
    primary key ((user_id), application_id, thumbprint)
) WITH transactional_mode = 'full';


