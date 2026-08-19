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
import com.github.adamorgan.jnt.api.managers.ProofObjectManager;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.applications.ApplicationSyncAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.api.utils.applications.ApplicationData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import com.reganjohn.jact.api.interactions.context.InteractionMapping;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ApplicationSyncActionImpl extends AbstractApplicationActionImpl implements ApplicationSyncAction
{
    public ApplicationSyncActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Applications.CREATE_APPLICATION_ACCESS);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleUniqueID(context, request, ((JacksonRequestBody) request.getBody()).getObject(), new ArrayList<>());
    }

    private void handleUniqueID(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull DataObject rawData,
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
            handleKeyword(context, request, rawData, schemaErrors);
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

    private void handleKeyword(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                               @Nonnull DataObject rawData,
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
            handleCanManage(context, request, rawData, schemaErrors);
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
                                 @Nonnull DataObject rawData,
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
            handleManage(context, request, rawData, schemaErrors);
        }
    }

    private void handleManage(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawData,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        if (Helpers.isEmpty(schemaErrors))
            handleAccessEntry(context, request, rawData, schemaErrors);
        else
            handleInternally(context, request, rawData, schemaErrors);
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
                                   @Nonnull DataObject rawData,
                                   @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        AccessEntryType type = AccessEntryType.valueOf(rawData.getString(ProofObjectManager.KTY).toUpperCase(Locale.ROOT));
        if (type == AccessEntryType.OKP || type == AccessEntryType.EC)
            handleCanAccess(context, request, rawData, schemaErrors);
        else
            handleUniqueId(context, request, rawData, schemaErrors);
    }

    private void handleCanAccess(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawData,
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
            handleUniqueId(context, request, rawData, schemaErrors);
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

    private void handleUniqueId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull DataObject rawData,
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
            handleAvailable(context, request, rawData, schemaErrors);
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

    private void handleAvailable(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawData,
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
            handleFields(context, request, rawData, schemaErrors);
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

    private void handleFields(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawData,
                              @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        AccessEntryType type = AccessEntryType.valueOf(rawData.getString(ProofObjectManager.KTY).toUpperCase(Locale.ROOT));
        for (String key : getFields(type))
            handleField(context, rawData, key, schemaErrors);
        handleAlgorithm(context, request, rawData, schemaErrors);
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

    private void handleAlgorithm(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
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
            handleCurve(context, request, rawData, schemaErrors);
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

    private void handleCurve(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
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
            handleInternally(context, request, rawData, schemaErrors);
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

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawBody,
                                  @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        AccessObjectData objectData = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        AccessEntryData entryData = AbstractEntityBuilder.createAccessEntry(rawBody);
        try (AccessContextData contextData = entryData.getContext(AccessContextType.SHA_256))
        {
            Map<String, String> params = request.getRoute().getMajorParameters();
            UUID userId = UUID.fromString(objectData.getSubject());
            UUID applicationId = UUID.fromString(params.get("application_id"));
            api.retrieveUserById(userId)
                    .flatMap(user -> user.retrieveApplicationById(applicationId))
                    .flatMap(application -> create(userId, application, entryData, contextData))
                    .flatMap(this::sync)
                    .queue(success -> handleSuccess(context), context::fireExceptionCaught);
        }
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<AccessCreateData> create(@Nonnull UUID userId, @Nonnull Application application,
                                                               @Nonnull AccessEntryData data,
                                                               @Nonnull AccessContextData context)
    {
        return application.retrieveAccessCount().map(count ->
        {
            return create(userId, application, count, data, context);
        });
    }

    @Nonnull
    private AccessCreateData create(@Nonnull UUID userId, @Nonnull Application application, int count,
                                    @Nonnull AccessEntryData entryData, @Nonnull AccessContextData contextData)
    {
        if (count > Application.MAX_ACCESS_ENTRY_COUNT)
            throw new ErrorResponseException(ErrorResponse.MAX_ACCESS_APPLICATION);
        else
            return new AccessCreateData(userId, application, entryData, 0, contextData.digest());
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> sync(@Nonnull AccessCreateData access)
    {
        Checks.notNull(access, "Application");
        return new InteractionMappingActionImpl<>(api.getJACT(), ClassLoader.getResourceAsString("create_access_application.cql"), access)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> interaction,
                                      @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    interaction.onSuccess(null);
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.ACCESS_ALREADY_EXISTS));
            }
        };
    }

    public void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.CREATED));
    }

    private static class AccessCreateData implements ApplicationData, InteractionMapping
    {
        private final UUID userId;
        private final Application application;
        private final AccessEntryData entryData;
        private final long flags;
        private final String thumbprint;

        public AccessCreateData(@Nonnull UUID userId, @Nonnull Application application, @Nonnull AccessEntryData data,
                                long flags, @Nonnull String thumbprint)
        {
            this.userId = userId;
            this.application = application;
            this.entryData = data;
            this.flags = flags;
            this.thumbprint = thumbprint;
        }

        @Nonnull
        public Map<String, Object> toMap()
        {
            return new InteractionMapping.Builder()
                    .put("user_id", userId)
                    .put("application_id", application.getUniqueId())
                    .put("owner_id", application.getOwnerId())
                    .put("alg", entryData.getAccessOption().getMode())
                    .put("flags", flags)
                    .put("kid", entryData.getName())
                    .put("kty", entryData.getType().name())
                    .put("usage", entryData.getUsage().name().toLowerCase())
                    .put("access_id", UUID.nameUUIDFromBytes(thumbprint.getBytes(StandardCharsets.UTF_8)))
                    .put("access_flags", 0L)
                    .put("thumbprint", thumbprint)
                    .put("public_key", entryData.getPublicKey().getEncoded())
                    .toMap();
        }

        @Nonnull
        @Override
        public DataObject toData()
        {
            return DataObject.fromMap(toMap());
        }
    }
}
