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

package com.github.reganjohn.iam.internal.requests.restactions.self;

import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.self.SelfUserDeleteAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractUserActionImpl;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class SelfUserDeleteActionImpl extends AbstractUserActionImpl implements SelfUserDeleteAction
{
    public SelfUserDeleteActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Self.DELETE_SELF);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        AccessObjectData objectData = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(objectData.getSubject());
        api.retrieveUserById(userId)
                .flatMap(User::delete)
                .queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    public void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new CaseInsensitiveMap<>()));
    }
}
