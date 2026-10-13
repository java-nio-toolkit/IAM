/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.internal.requests.restactions.sessions;

import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.SerializableData;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.sessions.SessionPaginationAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractSessionActionImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import io.netty.channel.ChannelHandlerContext;
import com.github.adamorgan.jnt.api.utils.collection.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.*;
import java.util.stream.Collectors;

public class SessionPaginationActionImpl extends AbstractSessionActionImpl implements SessionPaginationAction
{
    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public SessionPaginationActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Session.GET_SESSIONS);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleInternally(context, retrieveSelfUserId(context));
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull UUID userId)
    {
        api.retrieveSessions(userId)
                .flatMap(sessions -> retrieveData(userId, sessions))
                .queue(successObj -> handleSuccess(context, successObj), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull DataArray successObj)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, successObj.toBinary(), true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<DataArray> retrieveData(@Nonnull UUID userId, @Nonnull List<Session> sessions)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(sessions, "Sessions");
        return retrieveMap(userId, sessions).map(data -> mapFromDataArray(sessions, data));
    }

    @Nonnull
    private DataArray mapFromDataArray(@Nonnull List<Session> sessions, @Nonnull Map<String, DataObject> map)
    {
        Checks.notNull(sessions, "Sessions");
        Checks.notNull(map, "Map");
        return sessions.stream().map(session -> retrieveAccessData(session, map)).collect(Helpers.toDataArray());
    }

    @Nonnull
    private InteractionCallbackAction<AccessEntryArray> retrieveAccessData(@Nonnull UUID userId,
                                                                           @Nonnull List<Session> sessions)
    {
        return api.retrieveAccess(userId).map(access -> filter(sessions, access));
    }

    @Nonnull
    private AccessEntryArray filter(@Nonnull List<Session> sessions, @Nonnull AccessEntryArray access)
    {
        Set<String> set = new HashSet<>(sessions.size());
        for (Session session : sessions)
            set.add(session.getThumbprint());
        List<AccessEntryData> raw = new ArrayList<>(access.size());
        for (AccessEntryData data : access)
        {
            try (AccessContextData context = data.getContext(AccessContextType.SHA_256))
            {
                if (set.contains(context.digest()))
                {
                    raw.add(data);
                }
            }
            catch (Exception ex)
            {
                throw new IllegalStateException("Failed to retrieve the snapshot hash", ex);
            }
        }
        return new AccessEntryArray(raw);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Map<String, DataObject>> retrieveMap(@Nonnull UUID userId,
                                                                           @Nonnull List<Session> sessions)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(sessions, "Sessions");
        return retrieveAccessData(userId, sessions).map(this::mapFromData);
    }

    @Nonnull
    private Map<String, DataObject> mapFromData(@Nonnull AccessEntryArray entries)
    {
        Checks.notNull(entries, "Access Entries");
        return entries.stream().map(SessionOverrideData::new).collect(Collectors.toMap(SessionOverrideData::getThumbprint, SessionOverrideData::toData));
    }

    @Nonnull
    public DataObject retrieveAccessData(@Nonnull Session session, @Nonnull Map<String, DataObject> map)
    {
        DataObject user = DataObject.empty()
                .put("user_id", session.getUserId())
                .toData();
        if (Helpers.nonEmpty(session.getUserAgent()))
            user.put("user_agent", session.getUserAgent());
        return DataObject.empty()
                .put("session_id", session.getUniqueId())
                .put("user", user)
                .put("jwk", map.get(session.getThumbprint()))
                .put("flags", session.getFlagsRaw())
                .toData();
    }

    private static class SessionOverrideData implements SerializableData
    {
        private final AccessEntryData entry;

        public SessionOverrideData(@Nonnull AccessEntryData data)
        {
            this.entry = data;
        }

        @Nonnull
        public String getThumbprint()
        {
            try (AccessContextData context = entry.getContext(AccessContextType.SHA_256))
            {
                return context.digest();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
        }

        @Nonnull
        @Override
        public DataObject toData()
        {
            return entry.toData();
        }
    }
}
