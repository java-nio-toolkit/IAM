package com.github.reganjohn.iam.internal.managers;

import com.github.adamorgan.jnt.api.exceptions.InvalidTokenException;
import com.github.adamorgan.jnt.api.utils.AccessUtil;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.managers.GlobalAccessManager;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.utils.AccessEntryFlag;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.api.utils.data.BufferObject;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.c4j.internal.utils.InteractionUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.HashedWheelTimer;
import org.apache.commons.lang3.exception.UncheckedException;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class GlobalAccessManagerImpl extends AccessEntryManagerImpl implements GlobalAccessManager
{
    private final IAMImpl api;

    public GlobalAccessManagerImpl(IAMImpl api, @Nonnull SignType type, int limit, long timeout,
                                   @Nonnull TimeUnit unit, @Nonnull List<String> audiences)
    {
        super(new HashedWheelTimer(1L, unit), type, limit, timeout, unit, audiences);
        this.api = api;
    }

    @Override
    public void handlerAdded(@Nonnull ChannelHandlerContext context)
    {
        try
        {
            context.channel().attr(IDENTIFIER).set(this);
        }
        finally
        {
            super.handlerAdded(context);
        }
    }

    @Override
    public void handlerRemoved(@Nonnull ChannelHandlerContext context) throws Exception
    {
        try
        {
            context.channel().attr(IDENTIFIER).set(null);
        }
        finally
        {
            super.handlerRemoved(context);
        }
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Boolean> hasAccess(@Nonnull AccessObjectData data)
    {
        return hasAccess(data.getOptionData().getEntryData(), data);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Boolean> checkAvailable(@Nonnull String thumbprint)
    {
        Checks.notEmpty(thumbprint, "Thumbprint");
        return new InteractionContextActionImpl<>(api.getJCA(), "SELECT * FROM global.public_keys WHERE thumbprint = ?", Collections.singletonList(thumbprint))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Boolean> interaction,
                                      @Nonnull BufferArray array)
            {
                interaction.onSuccess(array.isEmpty() || EntityBuilder.isDelete(array));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Boolean> hasAccess(AccessEntryData raw, @Nonnull AccessObjectData data)
    {
        Checks.check(raw != null, "The token must contain its JWK in the header.");
        try (AccessContextData context = raw.getContext(AccessContextType.SHA_256))
        {
            return hasAccess(context, data);
        }
        catch (Exception ex)
        {
            throw new UncheckedException(ex);
        }
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Boolean> hasAccess(@Nonnull AccessContextData context, @Nonnull AccessObjectData data)
    {
        return new InteractionContextActionImpl<>(api.getJCA(), "SELECT * FROM global.public_keys WHERE thumbprint = ?", Collections.singletonList(context.digest()))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Boolean> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (!array.isEmpty() && !EntityBuilder.isDelete(array))
                    interaction.onSuccess(hasAccess(data, array.getObject(0)));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SIGNER));
            }
        };
    }

    private boolean hasAccess(@Nonnull AccessObjectData rawData, @Nonnull BufferObject successObj) throws GeneralSecurityException
    {
        EnumSet<AccessEntryFlag> flags = AccessEntryFlag.getFlags(successObj.getLong("flags"));
        if (!flags.contains(AccessEntryFlag.ISSUED))
            throw new InvalidTokenException();
        String mode = successObj.getString("alg");
        X509EncodedKeySpec engine = new X509EncodedKeySpec(successObj.getBytes("public_key"));
        KeyFactory factory = KeyFactory.getInstance(mode);
        PublicKey key = factory.generatePublic(engine);
        return AccessUtil.checkAccess(key, SignType.from(mode), rawData.getRawHeaders(), rawData.getRawBody(), rawData.getRawSign());
    }

    @Override
    protected void onCreateSnapshot(@Nonnull AccessEntrySnapshot snapshot)
    {
        onCreateSnapshot(snapshot, mapFromData(snapshot)).queue(success -> super.onCreateSnapshot(snapshot), Throwable::printStackTrace);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> onCreateSnapshot(@Nonnull AccessEntrySnapshot snapshot,
                                                             @Nonnull Map<String, Object> contextMap)
    {
        Checks.notNull(snapshot, "Snapshot");
        Checks.notNull(contextMap, "Map");
        return new InteractionMappingActionImpl<>(api.getJCA(), ClassLoader.getResourceAsString("create_issued_signer.cql"), mapFromData(snapshot))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> interaction,
                                      @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    interaction.onSuccess(null);
                else
                    throw new ErrorResponseException(ErrorResponse.ACCESS_ALREADY_EXISTS);
            }
        };
    }

    @Nonnull
    @Unmodifiable
    private Map<String, Object> mapFromData(@Nonnull AccessEntrySnapshot snapshot)
    {
        Checks.check(snapshot.getType() != AccessEntryType.NONE, "The snapshot type cannot be NONE.");
        try (AccessContextData context = snapshot.getContext(AccessContextType.SHA_256))
        {
            return new InteractionMapping.Builder()
                    .put("kid", snapshot.getUniqueId())
                    .put("alg", getSignType().getName())
                    .put("kty", snapshot.getType().name())
                    .put("usage", snapshot.getUsage().name())
                    .put("flags", AccessEntryFlag.getRaw(AccessEntryFlag.ISSUED))
                    .put("thumbprint", context.digest())
                    .put("public_key", snapshot.getPublic().getEncoded())
                    .toMap();
        }
        catch (Exception ex)
        {
            throw new IllegalStateException("Failed to retrieve the snapshot hash", ex);
        }
    }
}
