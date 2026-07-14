package com.github.reganjohn.iam.internal.managers;

import com.github.adamorgan.jnt.api.utils.AccessUtil;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.managers.GlobalAccessEntryManager;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.interactions.context.InteractionMapping;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.api.utils.data.BufferObject;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.jact.internal.utils.InteractionUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.AttributeKey;
import io.netty.util.HashedWheelTimer;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class GlobalAccessEntryManagerImpl extends AccessEntryManagerImpl implements GlobalAccessEntryManager
{
    public static final AttributeKey<GlobalAccessEntryManagerImpl> IDENTIFIER = AttributeKey.valueOf("access.entry.manager");

    private final IAMImpl api;

    public GlobalAccessEntryManagerImpl(IAMImpl api, @Nonnull SignType type, int limit, long timeout,
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
    public InteractionCallbackAction<Boolean> hasAccess(@Nonnull UUID id, @Nonnull AccessObjectData data)
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM global.public_keys WHERE kid = ?", Collections.singletonList(id))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Boolean> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (array.isEmpty())
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SIGNER));
                else
                    interaction.onSuccess(hasAccess(data, array.getObject(0)));
            }
        };
    }

    private boolean hasAccess(@Nonnull AccessObjectData rawData, @Nonnull BufferObject successObj) throws GeneralSecurityException
    {
        String mode = successObj.getString("alg");
        X509EncodedKeySpec engine = new X509EncodedKeySpec(successObj.getBytes("public_key"));
        KeyFactory factory = KeyFactory.getInstance(mode);
        PublicKey key = factory.generatePublic(engine);
        return AccessUtil.checkAccess(key, SignType.from(mode), rawData.getRawHeaders(), rawData.getRawBody(), rawData.getRawSign());
    }

    @Override
    protected void onCreateSnapshot(@Nonnull AccessEntrySnapshot snapshot)
    {
        onCreateSnapshot(snapshot, mapFromData(snapshot));
    }

    private void onCreateSnapshot(@Nonnull AccessEntrySnapshot snapshot, @Nonnull Map<String, Object> contextMap)
    {
        Checks.notNull(snapshot, "Snapshot");
        Checks.notNull(contextMap, "Map");
        String content = Helpers.format("INSERT INTO global.public_keys (%s) VALUES (%s) IF NOT EXISTS",
                Helpers.join(", ", contextMap.keySet()),
                Helpers.join(", ", InteractionUtil.split(contextMap.keySet(), true)));
        new InteractionMappingActionImpl<Void>(api.getJACT(), content, mapFromData(snapshot))
                .queue(success -> super.onCreateSnapshot(snapshot), Throwable::printStackTrace);
    }

    @Nonnull
    @Unmodifiable
    private Map<String, Object> mapFromData(@Nonnull AccessEntrySnapshot snapshot)
    {
        Checks.check(snapshot.getType() != AccessEntryType.NONE, "The snapshot type cannot be NONE.");
        try (AccessContextData contextData = snapshot.getContext(AccessContextType.SHA_256))
        {
            return new InteractionMapping.Builder()
                    .put("kid", snapshot.getUniqueId())
                    .put("alg", getSignType().getName())
                    .put("kty", snapshot.getType().name())
                    .put("usage", snapshot.getUsage().name())
                    .put("thumbprint", contextData.digest())
                    .put("public_key", snapshot.getPublicKey().getEncoded())
                    .put("created_at", snapshot.getTimeCreated())
                    .put("expires_at", snapshot.getTimeExpiresAt())
                    .toMap();
        }
        catch (Exception ex)
        {
            throw new IllegalStateException("Failed to retrieve the snapshot hash", ex);
        }
    }
}
