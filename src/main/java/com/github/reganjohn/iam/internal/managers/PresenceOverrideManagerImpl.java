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

package com.github.reganjohn.iam.internal.managers;

import com.github.adamorgan.jnt.api.interactions.middle.digest.ContentAssertionRequest;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ClassicObjectManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.managers.PresenceOverrideManager;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.security.KeyPair;
import java.time.OffsetDateTime;

import static com.github.adamorgan.jnt.api.managers.DigestObjectManager.CONTENT_DIGEST;
import static com.github.adamorgan.jnt.api.managers.PresenceObjectManager.SIGN;
import static com.github.adamorgan.jnt.api.managers.PresenceObjectManager.SIGN_IN;

public class PresenceOverrideManagerImpl extends ClassicObjectManagerImpl implements PresenceOverrideManager
{
    private final AccessEntryManagerImpl manager;

    public PresenceOverrideManagerImpl(@Nonnull AccessEntryManager manager)
    {
        this.manager = (AccessEntryManagerImpl) manager;
    }

    @Override
    public void write1(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                       ChannelPromise promise) throws Exception
    {
        CaseInsensitiveMap<String, String> headers = request.getHeaders();
        ContentAssertionRequest content = buildInternally(request, manager.getCurrentOrder());
        headers.put(SIGN_IN, content.toString());
        headers.put(SIGN, content.sign());
        super.write1(context, request, promise);
    }

    @Override
    protected boolean acceptOutboundMessage1(@Nonnull Request request)
    {
        return !request.getRoute().getBaseRoute().isInteraction();
    }

    @Nonnull
    private ContentAssertionRequest buildInternally(@Nonnull Request request,
                                                    @Nonnull AccessEntryManagerImpl.AccessEntrySnapshot snapshot)
    {
        CaseInsensitiveMap<String, String> headers = request.getHeaders();
        Route.CompiledRoute route = request.getRoute();
        KeyPair secret = snapshot.getSecret();
        Checks.notNull(secret, "The Secret");
        return new ContentAssertionRequest.Builder(secret)
                .setContentDigest(headers.get(CONTENT_DIGEST))
                .setBody(request.getBody())
                .setMethod(route.getMethod())
                .setAuthority(request.getHeaders().get("Host"))
                .setCompiledRoute("/" + route.getCompiledRoute())
                .setCreationTimestamp(OffsetDateTime.now().toEpochSecond())
                .setTimeExpiresAt(snapshot.getTimeExpiresAt())
                .setUniqueId(snapshot.getUniqueId())
                .setMode(snapshot.getMode().getName())
                .build();
    }
}
