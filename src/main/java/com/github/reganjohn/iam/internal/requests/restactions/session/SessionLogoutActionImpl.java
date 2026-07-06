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
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.api.requests.Routes;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.security.PublicKey;
import java.util.UUID;

public class SessionLogoutActionImpl extends AbstractSessionActionImpl
{
    protected static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public SessionLogoutActionImpl(IAMImpl api)
    {
        super(api, Routes.Session.REMOVE_ALL_SESSIONS);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        ProofObjectData data = context.channel().attr(ProofObjectManagerImpl.CONTEXT).get();
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        String subject = json.getSubject();
        UUID userId = UUID.fromString(subject);
        PublicKey publicKey = data.getEntryData().getPublicKey();
        UUIDv7 sessionId = UUIDv7.nameUUIDFromBytes(publicKey.getEncoded());
        api.logout(userId, sessionId.toUUID()).queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new CaseInsensitiveMap<>()));
    }
}
