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

DROP TABLE IF EXISTS users.public_keys;
DROP TABLE IF EXISTS users.accounts;
DROP TABLE IF EXISTS users.sessions;
DROP TABLE IF EXISTS users.entitlements;

DROP TABLE IF EXISTS integrations.applications;
DROP TABLE IF EXISTS integrations.interactions;
DROP TABLE IF EXISTS integrations.responses;
DROP TABLE IF EXISTS integrations.public_keys;

CREATE TABLE IF NOT EXISTS global.public_keys
(
    kid        TEXT,
    alg        TEXT,
    kty        TEXT,
    usage      TEXT,
    thumbprint TEXT,
    public_key BLOB,
    PRIMARY KEY (thumbprint)
) WITH transactional_mode = 'full';

CREATE TABLE IF NOT EXISTS users.public_keys
(
    user_id    UUID,
    kid        TEXT,
    alg        TEXT,
    kty        TEXT,
    usage      TEXT,
    thumbprint TEXT,
    public_key BLOB,
    PRIMARY KEY ((user_id), thumbprint)
) WITH transactional_mode = 'full';

CREATE TABLE IF NOT EXISTS users.accounts
(
    user_id   UUID,
    flags     INT,
    username  TEXT,
    avatar_id TEXT,
    PRIMARY KEY (user_id)
) WITH transactional_mode = 'full';

CREATE TABLE IF NOT EXISTS users.sessions
(
    user_id    UUID,
    session_id UUID,
    flags      INT,
    user_agent TEXT,
    thumbprint TEXT,
    PRIMARY KEY ((user_id), session_id)
) WITH transactional_mode = 'full';

CREATE TABLE IF NOT EXISTS users.entitlements
(
    user_id        UUID,
    application_id UUID,
    owner_id       UUID,
    permissions    INT,
    updated_at     TIMESTAMP,
    PRIMARY KEY ((user_id), application_id)
) WITH transactional_mode = 'full';

CREATE TABLE IF NOT EXISTS integrations.applications
(
    user_id        UUID,
    application_id UUID,
    name           TEXT,
    description    TEXT,
    icon_id        TEXT,
    flags          INT,
    redirect_uris  LIST<TEXT>,
    PRIMARY KEY ((user_id), application_id)
) WITH transactional_mode = 'full';

CREATE TABLE IF NOT EXISTS integrations.interactions
(
    user_id        UUID,
    application_id UUID,
    interaction_id UUID,
    permissions    INT,
    redirect_uri   TEXT,
    expiry         TIMESTAMP,
    PRIMARY KEY ((user_id, application_id), interaction_id)
) WITH transactional_mode = 'full' AND DEFAULT_TIME_TO_LIVE = 300;

CREATE TABLE IF NOT EXISTS integrations.responses
(
    application_id UUID,
    interaction_id UUID,
    user_id        UUID,
    owner_id       UUID,
    permissions    INT,
    PRIMARY KEY ((application_id), interaction_id)
) WITH transactional_mode = 'full' AND DEFAULT_TIME_TO_LIVE = 60;

CREATE TABLE IF NOT EXISTS integrations.public_keys
(
    user_id        UUID,
    application_id UUID,
    thumbprint     TEXT,
    PRIMARY KEY ((user_id), application_id, thumbprint)
) WITH transactional_mode = 'full';


