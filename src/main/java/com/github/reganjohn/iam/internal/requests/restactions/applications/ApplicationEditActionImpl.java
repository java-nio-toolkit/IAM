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

import com.fasterxml.jackson.databind.JsonNode;
import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.internal.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.applications.ApplicationEditAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.api.utils.applications.ApplicationEditData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.c4j.internal.utils.InteractionUtil;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

public class ApplicationEditActionImpl extends AbstractApplicationActionImpl implements ApplicationEditAction
{
    public ApplicationEditActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Applications.EDIT_APPLICATION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        RequestBody body = request.getBody();
        if (!(body instanceof JacksonRequestBody && ((JacksonRequestBody) body).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleUniqueID(context, request, ((JacksonRequestBody) body).getObject(), new ArrayList<>());
    }

    private void handleUniqueID(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull DataObject json,
                                @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
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
            handleName(context, request, json, schemaErrors);
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

    private void handleName(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                            @Nonnull DataObject rawBody,
                            @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkName(rawBody);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("name", ex, schemaErrors);
        }
        finally
        {
            handleDescription(context, request, rawBody, schemaErrors);
        }
    }

    private void checkName(@Nonnull DataObject body)
    {
        if (!body.hasKey("name"))
            return;
        else if (!body.isType("name", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"name\" value is not string.");
        else if (body.isEmpty("name"))
            throw new DataObjectParsingException(STRING_TYPE_MIN, "The \"name\" value may not be empty");
        else if (body.getString("name").length() > Application.MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"name\" may not be longer than %d characters.", Application.MAX_NAME_LENGTH));
    }

    private void handleDescription(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull DataObject rawBody,
                                   @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkDescription(rawBody);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("description", ex, schemaErrors);
        }
        finally
        {
            handleIconId(context, request, rawBody, schemaErrors);
        }
    }

    private void checkDescription(@Nonnull DataObject body)
    {
        if (body.isEmpty("description"))
            return;
        else if (!body.isType("description", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"description\" value is not string.");
        else if (body.getString("description").length() > Application.MAX_DESCRIPTION_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"description\" may not be longer than %d characters.", Application.MAX_DESCRIPTION_LENGTH));
    }

    private void handleIconId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawData,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkIconId(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("icon_id", ex, schemaErrors);
        }
        finally
        {
            handleFlags(context, request, rawData, schemaErrors);
        }
    }

    private void checkIconId(@Nonnull DataObject body)
    {
        if (!body.hasKey("icon_id"))
            return;
        else if (!body.isType("icon_id", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"icon_id\" value is not string.");
        else if (body.getString("icon_id").length() > Application.ICON_CID_MAX_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"icon_id\" may not be longer than %d characters.", Application.ICON_CID_MAX_LENGTH));
    }

    private void handleFlags(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                             @Nonnull DataObject rawBody,
                             @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkFlags(rawBody);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("flags", ex, schemaErrors);
        }
        finally
        {
            handleRedirectUris(context, request, rawBody, schemaErrors);
        }
    }

    private void checkFlags(@Nonnull DataObject body)
    {
        if (!body.hasKey("flags"))
            return;
        else if (!body.isType("flags", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE, "Value \"flags\" is not number.");
        else if (body.getInt("flags") < 0)
            throw new DataObjectParsingException(NUMBER_TYPE_MIN,
                    "Value \"flags\" should be greater than or equal to 0.");
    }

    private void handleRedirectUris(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                    @Nonnull DataObject rawBody,
                                    @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            if (!rawBody.hasKey("redirect_uris"))
                return;
            else if (!rawBody.isType("redirect_uris", DataType.ARRAY))
                throw new DataObjectParsingException(MODEL_TYPE_CONVERT, "Expected an object/dictionary.");
            else
                checkRedirectUris(rawBody.getArray("redirect_uris"));
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("redirect_uris", ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, request, rawBody, schemaErrors);
        }
    }

    private void checkRedirectUris(@Nonnull DataArray array)
    {
        if (array.isEmpty())
            throw new DataObjectParsingException(BASE_TYPE_MIN_LENGTH, "The \"redirect_uris\" value may not be empty.");
        else if (array.size() > Application.MAX_URL_COUNT)
            throw new DataObjectParsingException(BASE_TYPE_MAX_LENGTH,
                    Helpers.format("Must be %s or fewer in length.", Application.MAX_URL_COUNT));
        else if (!Helpers.exists(array, JsonNode::isTextual))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"redirect_urls\" contains value which is not a string.");
        else if (!Helpers.exists(array, node -> MiscUtil.isURL(node.textValue(), false)))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "The \"redirect_urls\" contains value which is not a url.");
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawBody,
                                  @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(json.getSubject());
        UUID applicationId = UUID.fromString(request.getRoute().getMajorParameters().get("application_id"));
        api.retrieveUserById(userId)
                .flatMap(user -> user.retrieveApplicationById(applicationId))
                .map(application -> fromData(application, rawBody))
                .flatMap(this::modify)
                .queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private ApplicationEditData fromData(@Nonnull Application application, @Nonnull DataObject json)
    {
        UUID applicationId = application.getUniqueId();
        UUID userId = application.getOwnerId();
        String name = json.getString("name", application.getName());
        String description = json.getString("description", application.getDescription());
        String iconId = json.getString("icon_id", application.getIconId());
        long flags = json.getLong("flags", application.getFlagsRaw());
        long base = application.getFlagsRaw() & Application.ApplicationFlag.SYSTEM;
        long modifiers = flags & ~Application.ApplicationFlag.SYSTEM;
        List<String> redirectUris = editRedirectUris(application, json);
        return new ApplicationEditData(userId, applicationId, name, description, iconId, base | modifiers, redirectUris);
    }

    @Nonnull
    private List<String> editRedirectUris(@Nonnull Application application, @Nonnull DataObject body)
    {
        return body.hasKey("redirect_uris") ? body.getArray("redirect_uris")
                .stream(DataArray::getString)
                .collect(Collectors.toList()) : application.getRedirectUris();
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> modify(@Nonnull ApplicationEditData application)
    {
        Checks.notNull(application, "Application");
        return new InteractionMappingActionImpl<>(api.getJCA(), ClassLoader.getResourceAsString("edit_application.cql"), application)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION));
            }
        };
    }

    public void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new CaseInsensitiveMap<>()));
    }
}
