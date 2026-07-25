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

import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.session.SessionLogoutAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.interactions.context.InteractionMapping;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class SessionLogoutActionImpl extends AbstractSessionActionImpl implements SessionLogoutAction
{
    public SessionLogoutActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Session.REMOVE_ALL_SESSIONS);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        ProofObjectData data = context.channel().attr(ProofObjectManagerImpl.CONTEXT).get();
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(json.getSubject());
        PublicKey publicKey = data.getEntryData().getPublicKey();
        UUIDv7 sessionId = UUIDv7.nameUUIDFromBytes(publicKey.getEncoded());
        api.retrieveUserById(userId)
                .flatMap(User::retrieveSessions)
                .map(sessions -> createPlaceholder(userId, sessionId.toUUID(), sessions))
                .flatMap(this::logout)
                .queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    @Nonnull
    private Placeholder createPlaceholder(@Nonnull UUID userId, @Nonnull UUID sessionId,
                                          @Nonnull List<Session> sessions)
    {
        Placeholder placeholder = new Placeholder(userId, sessionId, sessions);
        if (placeholder.sessions.isEmpty())
            throw new ErrorResponseException(ErrorResponse.CANNOT_CLOSE_SINGLE_SESSION);
        else
            return placeholder;
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> logout(@Nonnull Placeholder placeholder)
    {
        String content = ClassLoader.getResourceAsString("logout.cql", placeholder.getSessions(), placeholder.getThumbprints());
        return new InteractionMappingActionImpl<>(api.getJACT(), content, placeholder.toMapping())
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> interaction,
                                      @Nonnull BufferArray array)
            {
                interaction.onSuccess(null);
            }
        };
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new CaseInsensitiveMap<>()));
    }

    private static class Placeholder
    {
        private final UUID userId;
        private final UUID sessionId;
        private final List<Session> sessions;

        private Placeholder(@Nonnull UUID userId, UUID sessionId, @Nonnull List<Session> sessions)
        {
            this.userId = userId;
            this.sessionId = sessionId;
            this.sessions = sessions.stream().filter(session -> !isOwner(session)).collect(Collectors.toList());
        }

        @Nonnull
        public String getSessions()
        {
            return IntStream.range(0, sessions.size()).mapToObj(i -> ":s" + i).collect(Collectors.joining(", "));
        }

        @Nonnull
        public String getThumbprints()
        {
            return IntStream.range(0, sessions.size()).mapToObj(i -> ":t" + i).collect(Collectors.joining(", "));
        }

        @Nonnull
        public InteractionMapping toMapping()
        {
            return new InteractionMapping.Builder(toMap())
                    .put("user_id", userId)
                    .build();
        }

        @Nonnull
        public Map<String, Object> toMap()
        {
            return IntStream.range(0, sessions.size()).collect(HashMap::new, this::withQueryParams, HashMap::putAll);
        }

        private void withQueryParams(@Nonnull Map<String, Object> map, int index)
        {
            Session session = sessions.get(index);
            map.put("s" + index, session.getUniqueId());
            map.put("t" + index, session.getThumbprint());
        }

        private boolean isOwner(@Nonnull Session session)
        {
            return session.getUniqueId().equals(sessionId);
        }
    }
}
