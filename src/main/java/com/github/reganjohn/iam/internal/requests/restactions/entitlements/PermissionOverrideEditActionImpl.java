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

package com.github.reganjohn.iam.internal.requests.restactions.entitlements;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.entitlements.PermissionOverrideEditAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.c4j.internal.utils.InteractionUtil;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class PermissionOverrideEditActionImpl extends AbstractApplicationActionImpl implements PermissionOverrideEditAction
{
    public PermissionOverrideEditActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Entitlements.EDIT_ENTITLEMENT);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        RequestBody body = request.getBody();
        if (!(body instanceof JacksonRequestBody && ((JacksonRequestBody) body).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleApplicationId(context, request, ((JacksonRequestBody) body).getObject(), new ArrayList<>());
    }

    private void handleApplicationId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull DataObject rawBody,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkApplicationId(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("application_id", ex, errors);
        }
        finally
        {
            handlePermissions(context, request, rawBody, errors);
        }
    }

    private void checkApplicationId(@Nonnull Map<String, String> params)
    {
        String id = params.get("application_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"application_id\" value is not uuid.");
    }

    private void handlePermissions(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull DataObject rawData,
                                   @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkPermissions(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("permissions", ex, errors);
        }
        finally
        {
            handleErrorResponse(context, request, rawData, errors);
        }
    }

    private void checkPermissions(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey("permissions"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!rawData.isType("permissions", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE, "Value \"permissions\" is not number.");
        else if (rawData.getLong("permissions") < 0)
            throw new DataObjectParsingException(NUMBER_TYPE_MIN, "Value \"permissions\" should be greater than or equal to 0.");
    }

    private void handleErrorResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull DataObject rawBody,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (errors.isEmpty())
            handleInternally(context, request, rawBody);
        else
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawBody)
    {
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID userId = retrieveSelfUserId(context);
        UUID applicationId = UUID.fromString(params.get("application_id"));
        api.retrieveUserById(userId)
                .flatMap(user -> user.retrieveEntitlementById(applicationId))
                .flatMap(entitlement -> modify(entitlement, rawBody))
                .queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> modify(@Nonnull PermissionOverride override, @Nonnull DataObject rawBody)
    {
        Checks.notNull(override, "Entitlement");
        Checks.notNull(rawBody, "Body");
        long permissions = rawBody.getLong("permissions", override.getPermissionsRaw());
        if ((permissions & ~(override.getPermissionsRaw() & Permission.getRaw(Permission.values()))) != 0)
            throw new ErrorResponseException(ErrorResponse.MISSING_ACCESS);
        InteractionMapping map = new InteractionMapping.Builder()
                .put("user_id", override.getUserId())
                .put("application_id", override.getApplicationId())
                .put("permissions", permissions)
                .put("updated_at", OffsetDateTime.now())
                .put("flags", override.getFlagsRaw())
                .put("current_permissions", override.getPermissionsRaw())
                .build();
        return new InteractionMappingActionImpl<>(api.getJCA(), "UPDATE users.entitlements SET permissions = :permissions, updated_at = :updated_at WHERE user_id = :user_id AND application_id = :application_id IF flags = :flags AND permissions = :current_permissions", map)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<Void> interaction,
                                      @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    interaction.onSuccess(null);
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_ENTITLEMENT));
            }
        };
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT));
    }
}
