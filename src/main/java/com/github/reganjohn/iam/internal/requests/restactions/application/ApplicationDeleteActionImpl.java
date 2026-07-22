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

package com.github.reganjohn.iam.internal.requests.restactions.application;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.ApplicationInfo;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.application.ApplicationDeleteAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.interactions.context.InteractionMapping;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.github.reganjohn.iam.api.requests.restactions.UserAction.BASE_TYPE_REQUIRED;
import static com.github.reganjohn.iam.api.requests.restactions.UserAction.UUID_TYPE_COERCE;

public class ApplicationDeleteActionImpl extends AbstractApplicationActionImpl implements ApplicationDeleteAction
{
    public ApplicationDeleteActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Applications.DELETE_APPLICATION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleUniqueID(context, request, new ArrayList<>());
    }

    private void handleUniqueID(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUniqueID(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("application_id", ex, schemaErrors);
        }
        finally
        {
            handleException(context, request, schemaErrors);
        }
    }

    private void checkUniqueID(@Nonnull Map<String, String> params)
    {
        String id = params.get("application_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"application_id\" value is not uuid.");
    }

    private void handleException(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        else
            handleInternally(context, request);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request)
    {
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(json.getSubject());
        UUID applicationId = UUID.fromString(request.getRoute().getMajorParameters().get("application_id"));
        retrieveApplicationInfo(userId, applicationId).queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> retrieveApplicationInfo(UUID userId, UUID applicationId)
    {
        return api.retrieveApplicationById(userId, applicationId)
                .flatMap(api::retrieveApplicationInfo)
                .map(Placeholder::new)
                .flatMap(this::delete);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> delete(@Nonnull Placeholder placeholder)
    {
        return new InteractionMappingActionImpl<>(api.getJACT(), ClassLoader.getResourceAsString("delete_application.cql", placeholder.getThumbprints()), placeholder.toMapping())
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> interaction,
                                      @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    interaction.onSuccess(null);
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION));
            }
        };
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new CaseInsensitiveMap<>()));
    }

    private static class Placeholder
    {
        private final ApplicationInfo application;
        private final List<String> thumbprints;

        private Placeholder(@Nonnull ApplicationInfo application)
        {
            this.application = application;
            this.thumbprints = application.getThumbprints();
        }

        @Nonnull
        public String getThumbprints()
        {
            return IntStream.range(0, thumbprints.size()).mapToObj(i -> ":a" + i).collect(Collectors.joining(", "));
        }

        @Nonnull
        public InteractionMapping toMapping()
        {
            return new InteractionMapping.Builder(toMap())
                    .put("user_id", application.getOwnerId())
                    .put("application_id", application.getUniqueId())
                    .build();
        }

        @Nonnull
        public Map<String, Object> toMap()
        {
            return IntStream.range(0, thumbprints.size()).collect(HashMap::new, this::withQueryParams, HashMap::putAll);
        }

        private void withQueryParams(@Nonnull Map<String, Object> map, int index)
        {
            map.put("a" + index, thumbprints.get(index));
        }
    }
}
