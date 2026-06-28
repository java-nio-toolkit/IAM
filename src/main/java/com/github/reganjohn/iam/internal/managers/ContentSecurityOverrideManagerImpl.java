/*
 * Copyright 2026 Ada Morgan, John Regan and the JNT contributors
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

import com.github.adamorgan.jnt.api.interactions.middle.content.ContentSecurityBuilder;
import com.github.adamorgan.jnt.api.interactions.middle.content.ContentSecurityContext;
import com.github.adamorgan.jnt.api.interactions.middle.content.ContentSecurityPolicy;
import com.github.adamorgan.jnt.api.interactions.middle.content.InteractionPermission;
import com.github.adamorgan.jnt.api.interactions.middle.content.context.*;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.internal.managers.AbstractInteractionObjectManagerImpl;
import io.netty.channel.ChannelHandlerContext;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class ContentSecurityOverrideManagerImpl extends AbstractInteractionObjectManagerImpl
{
    private static final int PERMISSIONS = InteractionPermission.ALL_INTENTS & ~InteractionPermission.getRaw(
            InteractionPermission.PUBLICKEY_CREDENTIALS_GET,
            InteractionPermission.STORAGE_ACCESS,
            InteractionPermission.WEB_SHARE,
            InteractionPermission.FULLSCREEN);

    private final Map<String, String> headers = new ConcurrentHashMap<>();

    @Override
    public void handleResponse(@Nonnull ChannelHandlerContext context, @Nullable Request request, @Nonnull Response response)
    {
        response.getHeaders().putAll(headers);
    }

    @Override
    public void handlerAdded(@Nonnull ChannelHandlerContext context) throws Exception
    {
        if (!headers.isEmpty())
            this.headers.clear();
        this.headers.putAll(mapFromData());
    }

    @Nonnull
    @Unmodifiable
    private static Map<String, String> mapFromData()
    {
        return getDefault();
    }

    @Nonnull
    @Unmodifiable
    private static Map<String, String> getDefault()
    {
        return new ContentSecurityBuilder()
                .setContentSecurityPolicy(getContentPolicy())
                .setTimeOutEnd(365, TimeUnit.DAYS, ContentSecurityContext.Type.PRELOAD)
                .setReferrerPolicy(ReferrerPolicy.STRICT_CROSS)
                .setHideContentTypeOption(true)
                .addInteractionEndpointUrl("default", "http://iam.com")
                .setInteractionContext(InteractionContextType.NONE, "default")
                .setInteractionContent(InteractionContentType.REQUIRE, "default")
                .setInteractionResource(InteractionResourceType.SAME_ORIGIN)
                .setPermittedPolicy(PermittedPolicy.NONE)
                .setDisabledPermission(InteractionPermission.getPermissions(PERMISSIONS))
                .withContentMode(ContentSecurityContext.Mode.BLOCK)
                .withContentFlag(ContentSecurityContext.Flag.DENY)
                .toMap();
    }

    @Nonnull
    private static ContentSecurityPolicy getContentPolicy()
    {
        return new ContentSecurityPolicy.Builder()
                .addOptions(ContentSecurityContext.DEFAULT, ContentSecurityContext.SELF)
                .addOptions(ContentSecurityContext.IMG, ContentSecurityContext.SELF, ContentSecurityContext.DATA)
                .addOptions(ContentSecurityContext.SCRIPT, ContentSecurityContext.SELF)
                .addOptions(ContentSecurityContext.STYLE, ContentSecurityContext.SELF, ContentSecurityContext.UNSAFE_INLINE)
                .addOptions(ContentSecurityContext.CONNECT, ContentSecurityContext.SELF)
                .addOptions(ContentSecurityContext.FRAME_ANCESTORS, ContentSecurityContext.NONE)
                .build();
    }

    @Override
    public boolean isSharable()
    {
        return true;
    }
}
