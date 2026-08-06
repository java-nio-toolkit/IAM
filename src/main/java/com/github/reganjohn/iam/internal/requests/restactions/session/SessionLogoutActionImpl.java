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
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.session.SessionLogoutAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.requests.objaction.InteractionContextType;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionListContextActionImpl;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.apache.commons.collections4.multimap.AbstractMultiValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

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
                .map(sessions -> createPlaceholder(sessionId.toUUID(), sessions))
                .flatMap(this::logout)
                .queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    @Nonnull
    private Placeholder createPlaceholder(@Nonnull UUID sessionId,
                                          @Nonnull List<Session> sessions)
    {
        Placeholder placeholder = new Placeholder(sessionId, sessions);
        if (placeholder.sessions.isEmpty())
            throw new ErrorResponseException(ErrorResponse.CANNOT_CLOSE_SINGLE_SESSION);
        else
            return placeholder;
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> logout(@Nonnull Placeholder placeholder)
    {
        Checks.notNull(placeholder, "Placeholder");
        return new InteractionListContextActionImpl<>(api.getJACT(), InteractionContextType.LOGGED, placeholder.toMap())
        {
            @Override
            protected void handleBufferedBody(@Nonnull InteractionCallbackResponseImpl response,
                                              InteractionImpl<Void> interaction, @Nonnull ByteBuf data)
            {
                super.handleBufferedBody(response, interaction, data);
            }
        };
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new CaseInsensitiveMap<>()));
    }

    private static class Placeholder
    {
        private final UUID sessionId;
        private final List<Session> sessions;

        private Placeholder(UUID sessionId, @Nonnull List<Session> sessions)
        {
            this.sessionId = sessionId;
            this.sessions = sessions.stream().filter(session -> !isOwner(session)).collect(Collectors.toList());
        }

        private boolean isOwner(@Nonnull Session session)
        {
            return session.getUniqueId().equals(sessionId);
        }

        @Nonnull
        private ArrayListValuedHashMap<String, List<Object>> toMap()
        {
            return sessions.stream().collect(ArrayListValuedHashMap::new, this::withQueryParam, AbstractMultiValuedMap::putAll);
        }

        private void withQueryParam(@Nonnull MultiValuedMap<String, List<Object>> map, @Nonnull Session session)
        {
            long flags = session.getFlagsRaw() | Session.SessionFlag.DELETED.getRawValue();
            map.put("UPDATE users.sessions SET flags = ? WHERE user_id = ? AND session_id = ?", Arrays.asList(flags, session.getUserId(), session.getUniqueId()));
        }
    }
}
