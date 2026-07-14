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

package com.github.reganjohn.iam.internal.requests.restactions.session;

import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.session.SessionPaginationAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
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
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        handleInternally(context, UUID.fromString(json.getSubject()));
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull UUID userId)
    {
        retrieveData(userId).queue(successObj ->
        {
            BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, successObj.toBinary(), true);
            context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
        }, context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<DataArray> retrieveData(@Nonnull UUID userId)
    {
        return api.retrieveSessions(userId).flatMap(sessions -> retrieveData(userId, sessions));
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<DataArray> retrieveData(@Nonnull UUID userId, @Nonnull List<Session> sessions)
    {
        return api.retrieveAccessEntries(userId).map(entries ->
        {
            Map<String, DataObject> set = entries.stream().collect(Collectors.toMap(AccessEntryData::getName, AccessEntryData::toData));
            DataArray array = DataArray.empty();
            for (Session session : sessions)
            {
                DataObject user = DataObject.empty()
                        .put("user_id", session.getUserId())
                        .toData();

                if (Helpers.nonEmpty(session.getUserAgent()))
                    user.put("user_agent", session.getUserAgent());

                DataObject data = DataObject.empty()
                        .put("session_id", session.getUniqueId())
                        .put("user", user)
                        .put("jwk", set.get(session.getKeyId()))
                        .put("flags", session.getFlagsRaw())
                        .toData();
                array.add(data);
            }

            return array;
        });
    }
}
