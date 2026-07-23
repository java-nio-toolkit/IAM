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

import com.fasterxml.jackson.databind.JsonNode;
import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.application.ApplicationCreateAction;
import com.github.reganjohn.iam.api.utils.applications.ApplicationCreateData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.github.reganjohn.iam.api.requests.restactions.UserAction.*;

public class ApplicationCreateActionImpl extends AbstractApplicationActionImpl implements ApplicationCreateAction
{
    public ApplicationCreateActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Applications.CREATE_APPLICATION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleName(context, request, ((JacksonRequestBody) request.getBody()).getObject(), new ArrayList<>());
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
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!body.isType("name", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"name\" value is not string.");
        else if (body.getString("name").length() < Application.MIN_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MIN,
                    Helpers.format("The \"name\" value may not be less than %f characters.", Application.MIN_NAME_LENGTH));
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
                throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
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
            handleInternally(context, rawBody, schemaErrors);
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

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody, @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        AccessObjectData objectData = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        create(rawBody, objectData).queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> create(@Nonnull DataObject rawBody, @Nonnull AccessObjectData data)
    {
        UUID userId = UUID.fromString(data.getSubject());
        UUIDv7 applicationId = UUIDv7.randomUUID();
        String name = rawBody.getString("name");
        String description = !rawBody.isEmpty("description") ? rawBody.getString("description") : null;
        String iconId = rawBody.getString("icon_id", null);
        int flags = rawBody.getInt("flags", 0) & ~Application.ApplicationFlag.SYSTEM;
        List<String> redirectUris = rawBody.getArray("redirect_uris").stream(DataArray::getString).collect(Collectors.toList());
        ApplicationCreateData createData = new ApplicationCreateData(userId, applicationId.toUUID(), name, description, iconId, flags, redirectUris);
        return api.retrieveApplicationCount(userId).flatMap(count -> create(createData, count));
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> create(ApplicationCreateData application, int count)
    {
        if (count <= MAX_APPLICATION_COUNT)
            return api.createApplication(application);
        else
            throw new ErrorResponseException(ErrorResponse.MAX_APPLICATION);
    }


    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT));
    }
}
