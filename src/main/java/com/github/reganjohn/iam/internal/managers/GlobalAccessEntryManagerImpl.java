package com.github.reganjohn.iam.internal.managers;

import com.github.adamorgan.jnt.api.utils.AccessUtil;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.AccessOptionData;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.managers.GlobalAccessEntryManager;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.api.utils.data.BufferObject;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionContextActionImpl;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.AttributeKey;
import io.netty.util.HashedWheelTimer;

import javax.annotation.Nonnull;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class GlobalAccessEntryManagerImpl extends AccessEntryManagerImpl implements GlobalAccessEntryManager
{
    public static final AttributeKey<GlobalAccessEntryManagerImpl> IDENTIFIER = AttributeKey.valueOf("access.entry.manager");

    private final IAMImpl api;

    public GlobalAccessEntryManagerImpl(IAMImpl api, @Nonnull SignType type, int limit, long timeout, @Nonnull TimeUnit unit, @Nonnull List<String> audiences)
    {
        super(new HashedWheelTimer(1L, unit), type, limit, timeout, unit, audiences);
        this.api = api;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext context)
    {
        context.channel().attr(IDENTIFIER).set(this);
        super.handlerAdded(context);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext context) throws Exception
    {
        context.channel().attr(IDENTIFIER).set(null);
        super.handlerRemoved(context);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Boolean> hasGlobalAccess(@Nonnull AccessObjectData rawData)
    {
        AccessOptionData optionData = rawData.getOptionData();
        Checks.check(MiscUtil.isUUID(optionData.getName()), ""); //todo: add message!
        UUID kid = UUID.fromString(optionData.getName());
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM users.public_keys WHERE kid = ?", Collections.singletonList(kid))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response, @Nonnull InteractionImpl<Boolean> interaction, @Nonnull BufferArray array)
            {
                try
                {
                    if (array.isEmpty())
                        interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SIGNER));
                    else
                        interaction.onSuccess(hasAccess(array.getObject(0)));
                }
                catch (Exception failure)
                {
                    interaction.onFailure(failure);
                }
            }

            private boolean hasAccess(@Nonnull BufferObject successObj) throws GeneralSecurityException
            {
                String header = rawData.getRawHeaders();
                String body = rawData.getRawBody();
                String sign = rawData.getRawSign();
                byte[] raw = successObj.getBytes("public_key");
                String mode = successObj.getString("alg");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(raw);
                KeyFactory keyFactory = KeyFactory.getInstance(mode);
                PublicKey key = keyFactory.generatePublic(keySpec);
                return AccessUtil.checkAccess(key, SignType.from(mode), header, body, sign);
            }
        };
    }

    @Override
    protected void onCreateSnapshot(@Nonnull AccessEntrySnapshot snapshot)
    {
        UUID uniqueId = snapshot.getUniqueId();
        byte[] publicKey = snapshot.getPublicKey().getEncoded();
        SignType signType = getSignType();
        OffsetDateTime timeCreated = snapshot.getTimeCreated();
        OffsetDateTime timeExpiresAt = snapshot.getTimeExpiresAt();
        String content = "INSERT INTO users.public_keys (kid, public_key, alg, created_at, expires_at) VALUES (?, ?, ?, ?, ?)";
        new InteractionContextActionImpl<>(api.getJACT(), content, Arrays.asList(uniqueId, publicKey, signType.getName(), timeCreated, timeExpiresAt))
                .queue(success ->
        {
            LOG.debug("Success add pair key."); //todo: replace message!
        }, Throwable::printStackTrace);
        super.onCreateSnapshot(snapshot);
    }
}
