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

package com.github.reganjohn.iam.internal.requests.restactions;

import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.c4j.api.JCA;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.Nonnull;

public class HealthRetrieveActionImpl extends AbstractOverrideActionImpl
{
    public HealthRetrieveActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Health.GET_HEALTH);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request)
    {
        if (api.getJCA().getStatus() == JCA.Status.READY)
            context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT));
        else
            context.writeAndFlush(new Response(context, StatusReason.SERVICE_UNAVAILABLE));
    }
}
