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

import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.interactions.ApplicationInteractionRetrieveAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.utils.PermissionUtil;
import io.netty.channel.ChannelHandlerContext;
import com.github.adamorgan.jnt.api.utils.collection.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

public class ApplicationInteractionRetrieveActionImpl extends ApplicationInteractionOverrideActionImpl implements ApplicationInteractionRetrieveAction
{
    public ApplicationInteractionRetrieveActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Interactions.RETRIEVE_APPLICATION_INTERACTION);
    }

    @Override
    protected void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request)
    {
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID ownerId = UUID.fromString(params.get("user_id"));
        UUID applicationId = UUID.fromString(params.get("application_id"));
        UUID interactionId = UUID.fromString(params.get("interaction_id"));
        api.retrieveUserById(ownerId)
                .flatMap(user -> user.retrieveApplicationById(applicationId))
                .flatMap(application -> application.retrieveInteractionById(interactionId).map(interaction -> fromData(application, interaction)))
                .queue(json -> handleSuccess(context, json), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull DataObject successObj)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, successObj.toBinary(), true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }

    @Nonnull
    private DataObject fromData(@Nonnull Application application, @Nonnull ApplicationContextInteraction interaction)
    {
        DataObject json = DataObject.empty()
                .put("interaction_id", interaction.getUniqueId())
                .put("application", fromApplication(application))
                .put("access", PermissionUtil.toDataArray(interaction.getPermissions()))
                .put("expires_in", Math.max(0, Duration.between(OffsetDateTime.now(), interaction.getTimeExpiresAt()).getSeconds()))
                .toData();
        if (interaction.getLabel() != null)
            json.put("label", interaction.getLabel());
        return json;
    }

    @Nonnull
    private DataObject fromApplication(@Nonnull Application application)
    {
        return DataObject.empty()
                .put("application_id", application.getUniqueId())
                .put("name", application.getName())
                .put("description", application.getDescription())
                .put("icon_id", application.getIconId())
                .put("origin", application.getOrigin())
                .toData();
    }
}
