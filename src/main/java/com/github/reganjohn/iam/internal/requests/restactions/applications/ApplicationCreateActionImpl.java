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

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.applications.ApplicationCreateAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.api.utils.applications.ApplicationCreateBuilder;
import com.github.reganjohn.iam.api.utils.applications.ApplicationCreateData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

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
            handleOrigin(context, request, rawBody, schemaErrors);
        }
    }

    private void checkName(@Nonnull DataObject body)
    {
        if (!body.hasKey("name"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!body.isType("name", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"name\" value is not string.");
        else if (body.isEmpty("name"))
            throw new DataObjectParsingException(STRING_TYPE_MIN, "The \"name\" value may not be empty.");
        else if (body.getString("name").length() > Application.MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"name\" may not be longer than %d characters.", Application.MAX_NAME_LENGTH));
    }

    private void handleOrigin(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawBody,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkOrigin(rawBody);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("origin", ex, schemaErrors);
        }
        finally
        {
            handleDescription(context, request, rawBody, schemaErrors);
        }
    }

    private void checkOrigin(@Nonnull DataObject body)
    {
        if (!body.hasKey("origin"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!body.isType("origin", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"origin\" value is not string.");
        else if (body.isEmpty("origin"))
            throw new DataObjectParsingException(STRING_TYPE_MIN, "The \"origin\" value may not be empty.");
        else if (!MiscUtil.isURL(body.getString("origin"), false))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value \"origin\" is not url.");
        else if (!MiscUtil.isURL(body.getString("origin"), true))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value \"origin\" is not safe.");
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
                                    @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
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
            handleErrorResponse("redirect_uris", ex, errors);
        }
        finally
        {
            handleException(context, rawBody, errors);
        }
    }

    private void handleException(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody, @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (errors.isEmpty())
            handleInternally(context, rawBody);
        else
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody)
    {
        UUID userId = retrieveSelfUserId(context);
        api.retrieveUserById(userId)
                .flatMap(User::retrieveApplicationCount)
                .map(count -> fromData(rawBody, userId, count))
                .flatMap(this::create)
                .queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private ApplicationCreateData fromData(@Nonnull DataObject rawBody, @Nonnull UUID userId, int count)
    {
        if (MiscUtil.isUnsafeURL(URI.create(rawBody.getString("origin"))))
            throw createErrorResponse("origin", new DataObjectParsingException(BASE_TYPE_CHOICES, "Value \"origin\" is not safe."));
        else if (count >= MAX_APPLICATION_COUNT)
            throw new ErrorResponseException(ErrorResponse.MAX_APPLICATIONS);
        UUIDv7 applicationId = UUIDv7.randomUUID();
        String name = rawBody.getString("name");
        String description = rawBody.getString("description", null);
        String iconId = rawBody.getString("icon_id", null);
        String origin = rawBody.getString("origin");
        long flags = rawBody.getLong("flags", 0) & ~Application.ApplicationFlag.SYSTEM;
        List<String> redirectUris = rawBody.getArray("redirect_uris").stream(DataArray::getString).collect(Collectors.toList());
        return new ApplicationCreateBuilder()
                .setOwnerId(userId)
                .setUniqueId(applicationId.toUUID())
                .setName(name)
                .setDescription(description)
                .setIconId(iconId)
                .setOrigin(origin)
                .setFlags(flags)
                .setRedirectUris(redirectUris)
                .build();
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> create(@Nonnull ApplicationCreateData application)
    {
        Checks.notNull(application, "Application");
        return new InteractionMappingActionImpl<>(api.getJCA(), ClassLoader.getResourceAsString("create_application.cql"), application)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.APPLICATION_ALREADY_EXISTS));
            }
        };
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.CREATED));
    }
}
