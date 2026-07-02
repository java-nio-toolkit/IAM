/*
 * Copyright 2026 Ada Morgan, John Regan and the JNT contributors
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

package com.github.reganjohn.iam.internal.requests.restactions.self;

import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.api.requests.Routes;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.Nonnull;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class SelfUserDeleteActionImpl extends AbstractSelfUserActionImpl
{
    public SelfUserDeleteActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Self.DELETE_SELF);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        AccessObjectData objectData = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        String subject = objectData.getSubject();
        if (MiscUtil.isUUID(subject))
            handleInternally(context, UUID.fromString(subject));
        else
            throw new ErrorResponseException(0, ""); //todo: add message!
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull UUID userId)
    {
        api.deleteUserById(userId).queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    public void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new ConcurrentHashMap<>()));
    }
}
