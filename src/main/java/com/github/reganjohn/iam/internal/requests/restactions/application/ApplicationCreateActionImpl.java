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
import com.github.adamorgan.jnt.api.managers.ProofObjectManager;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
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
import io.netty.util.NetUtil;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

import static com.github.reganjohn.iam.api.requests.restactions.UserAction.*;
import static com.github.reganjohn.iam.api.requests.restactions.UserAction.BASE_TYPE_REQUIRED;
import static com.github.reganjohn.iam.api.requests.restactions.UserAction.STRING_TYPE_COERCE;

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
            handleFlags(context, request, rawBody, schemaErrors);
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
            handleAccess(context, request, rawBody, schemaErrors);
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

    private void handleAccess(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawBody,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkAccess(rawBody);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.KEY, ex, schemaErrors);
        }
        finally
        {
            handleKeyword(context, request, rawBody, rawBody.getObject(ProofObjectManager.KEY), schemaErrors);
        }
    }

    private void checkAccess(@Nonnull DataObject rawBody)
    {
        if (!rawBody.hasKey(ProofObjectManager.KEY))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawBody.isType(ProofObjectManager.KEY, DataType.OBJECT))
            throw new DataObjectParsingException(DICT_TYPE_CONVERT, "Only dictionaries may be used in a DictType.");
    }

    private void handleKeyword(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                               @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                               @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkKeyword(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.KTY, ex, schemaErrors);
        }
        finally
        {
            handleCanManage(context, request, rawBody, rawData, schemaErrors);
        }
    }

    private void checkKeyword(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.KTY))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.KTY, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.KTY));
        else if (!Helpers.contains(IAMImpl.signTypes.keySet(), rawData.getString(ProofObjectManager.KTY), true))
            throw createParsingException(ProofObjectManager.KTY, IAMImpl.signTypes.keySet());
    }

    private void handleCanManage(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkCanManage(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.USE, ex, schemaErrors);
        }
        finally
        {
            handleManage(context, request, rawBody, rawData, schemaErrors);
        }
    }

    private void handleManage(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        if (Helpers.isEmpty(schemaErrors))
            handleAccessEntry(context, request, rawBody, rawData, schemaErrors);
        else
            handleInternally(context, rawBody, rawData, schemaErrors);
    }

    private void checkCanManage(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.USE))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.USE, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.USE));
        else if (!Helpers.equals(rawData.getString(ProofObjectManager.USE), "sig", true))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value must be sig.");
    }

    private void handleAccessEntry(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                                   @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        AccessEntryType type = AccessEntryType.valueOf(rawData.getString(ProofObjectManager.KTY).toUpperCase(Locale.ROOT));
        if (type == AccessEntryType.OKP || type == AccessEntryType.EC)
            handleCanAccess(context, rawBody, rawData, schemaErrors);
        else
            handleUniqueId(context, rawBody, rawData, schemaErrors);
    }

    private void handleCanAccess(@Nonnull ChannelHandlerContext context,
                                 @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkCanAccess(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.CRV, ex, schemaErrors);
        }
        finally
        {
            handleUniqueId(context, rawBody, rawData, schemaErrors);
        }
    }

    private void checkCanAccess(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.CRV))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.CRV, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.CRV));
        else if (!canAccess(rawData.getString(ProofObjectManager.KTY), rawData.getString(ProofObjectManager.CRV)))
            throw createParsingException(ProofObjectManager.CRV, IAMImpl.signTypes.get(rawData.getString(ProofObjectManager.KTY)));
    }

    private boolean canAccess(String type, String crv)
    {
        return Helpers.contains(IAMImpl.signTypes.get(type), crv, true);
    }

    private void handleUniqueId(@Nonnull ChannelHandlerContext context,
                                @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                                @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUniqueId(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.KID, ex, schemaErrors);
        }
        finally
        {
            handleAvailable(context, rawBody, rawData, schemaErrors);
        }
    }

    private void checkUniqueId(@Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(ProofObjectManager.KID))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.KID, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.KID));
    }

    private void handleAvailable(@Nonnull ChannelHandlerContext context,
                                 @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkAvailable(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.ALG, ex, schemaErrors);
        }
        finally
        {
            handleFields(context, rawBody, rawData, schemaErrors);
        }
    }

    private void checkAvailable(@Nonnull DataObject rawData)
    {
        String type = rawData.getString(ProofObjectManager.KTY);
        if (!rawData.hasKey(ProofObjectManager.ALG))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.hasKey(ProofObjectManager.ALG, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", ProofObjectManager.ALG));
        else if (!Helpers.contains(IAMImpl.signTypes.get(type), rawData.getString(ProofObjectManager.ALG), true))
            throw createParsingException(ProofObjectManager.ALG, IAMImpl.signTypes.get(type));
    }

    private void handleFields(@Nonnull ChannelHandlerContext context,
                              @Nonnull DataObject rawBody, @Nonnull DataObject rawData,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        AccessEntryType type = AccessEntryType.valueOf(rawData.getString(ProofObjectManager.KTY).toUpperCase(Locale.ROOT));
        for (String key : getFields(type))
            handleField(context, rawData, key, schemaErrors);
        handleAlgorithm(context, rawBody, rawData, schemaErrors);
    }

    private void handleField(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawData,
                             @Nonnull String key, @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkField(key, rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(key, ex, schemaErrors);
        }
    }

    private void checkField(@Nonnull String key, @Nonnull DataObject rawData)
    {
        if (!rawData.hasKey(key))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required.");
        else if (!rawData.isType(key, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", key));
    }

    @Nonnull
    private List<String> getFields(@Nonnull AccessEntryType type)
    {
        switch (type)
        {
            case RSA:
                return Helpers.listOf("n", "e");
            case EC:
                return Helpers.listOf("x", "y");
            case OKP:
                return Helpers.listOf("x");
            default:
                return Collections.emptyList();
        }
    }

    private void handleAlgorithm(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody,
                                 @Nonnull DataObject rawData,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkAlgorithm(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.ALG, ex, schemaErrors);
        }
        finally
        {
            handleCurve(context, rawBody, rawData, schemaErrors);
        }
    }

    private void checkAlgorithm(@Nonnull DataObject rawData)
    {
        SignType signType = SignType.from(rawData.getString(ProofObjectManager.ALG));
        String type = rawData.getString(ProofObjectManager.KTY);
        if (signType == SignType.NONE || signType == SignType.UNKNOWN)
            throw createParsingException(ProofObjectManager.ALG, IAMImpl.signTypes.get(type));
        else if (!Helpers.equals(signType.getType(), type, true))
            throw createParsingException(ProofObjectManager.ALG, signType);
    }

    private void handleCurve(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody,
                             @Nonnull DataObject rawData,
                             @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkCurve(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(ProofObjectManager.CRV, ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, rawBody, rawData, schemaErrors);
        }
    }

    private void checkCurve(@Nonnull DataObject rawData)
    {
        SignType signType = SignType.from(rawData.getString(ProofObjectManager.ALG));
        String type = rawData.getString(ProofObjectManager.KTY);
        String crv = rawData.getString(ProofObjectManager.CRV);
        if (signType == SignType.NONE || signType == SignType.UNKNOWN)
            throw createParsingException(ProofObjectManager.CRV, IAMImpl.signTypes.get(type));
        else if (signType.hasExtension() && !Helpers.equals(crv, signType.getRawName(), true))
            throw createParsingException(ProofObjectManager.CRV, signType);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody,
                                  @Nonnull DataObject rawData,
                                  @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        AccessObjectData objectData = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        AccessEntryData entryData = AbstractEntityBuilder.createAccessEntry(rawData);
        try (AccessContextData contextData = entryData.getContext(AccessContextType.SHA_256))
        {
            create(rawBody, entryData, contextData, objectData).queue(success -> handleSuccess(context), context::fireExceptionCaught);
        }
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> create(@Nonnull DataObject rawBody, @Nonnull AccessEntryData entryData,
                                                   @Nonnull AccessContextData context, @Nonnull AccessObjectData data)
    {
        UUID userId = UUID.fromString(data.getSubject());
        UUIDv7 applicationId = UUIDv7.randomUUID();
        String name = rawBody.getString("name");
        String description = !rawBody.isEmpty("description") ? rawBody.getString("description") : null;
        String thumbprint = context.digest();
        int flags = rawBody.getInt("flags", 0) & ~Application.ApplicationFlag.SYSTEM;
        List<String> redirectUris = rawBody.getArray("redirect_uris").stream(DataArray::getString).collect(Collectors.toList());
        ApplicationCreateData createData = new ApplicationCreateData(userId, applicationId.toUUID(), name, description, entryData, flags, redirectUris, thumbprint);
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
