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

package com.github.reganjohn.iam.internal.requests.restactions.applications;

import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.applications.ApplicationPaginationAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.UUID;

public class ApplicationPaginationActionImpl extends AbstractApplicationActionImpl implements ApplicationPaginationAction
{
    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public ApplicationPaginationActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Applications.GET_SELF_APPLICATIONS);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleInternally(context, retrieveSelfUserId(context));
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull UUID userId)
    {
        api.retrieveUserById(userId)
                .flatMap(User::retrieveApplications)
                .map(this::fromData)
                .queue(json -> handleSuccess(context, json), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull DataArray successObj)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, successObj.toBinary(), true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }

    @Nonnull
    private DataArray fromData(@Nonnull List<Application> applications)
    {
        return applications.stream().map(this::fromData).collect(Helpers.toDataArray());
    }

    @Nonnull
    private DataObject fromData(@Nonnull Application application)
    {
        return DataObject.empty()
                .put("user_id", application.getOwnerId())
                .put("application_id", application.getUniqueId())
                .put("name", application.getName())
                .put("origin", application.getOrigin())
                .put("description", application.getDescription())
                .put("icon_id", application.getIconId())
                .put("flags", application.getFlagsRaw())
                .put("redirect_uris", application.getRedirectUris())
                .toData();
    }
}
