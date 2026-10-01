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


package com.github.reganjohn.iam.internal.requests.restactions.interactions;

import com.github.reganjohn.iam.api.events.applications.interactions.InteractionDeleteEvent;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.interactions.ApplicationInteractionDeleteAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.UUID;

public class ApplicationInteractionDeleteActionImpl extends ApplicationInteractionOverrideActionImpl implements ApplicationInteractionDeleteAction
{
    public ApplicationInteractionDeleteActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Interactions.DENY_APPLICATION_INTERACTION);
    }

    @Nonnull
    @Override
    @CheckReturnValue
    public InteractionCallbackAction<ApplicationContextInteraction> createResponse(@Nonnull UUID userId, @Nonnull String userThumbprint,
                                                                                   @Nonnull String reference,
                                                                                   @Nonnull ApplicationContextInteraction interaction)
    {
        return createResponse(userId, userThumbprint, reference, interaction, true).map(unused -> interaction);
    }

    @Override
    protected void onEvent(@Nonnull ChannelHandlerContext context, @Nonnull ApplicationContextInteraction interaction)
    {
        context.fireUserEventTriggered(new InteractionDeleteEvent(interaction));
    }
}
