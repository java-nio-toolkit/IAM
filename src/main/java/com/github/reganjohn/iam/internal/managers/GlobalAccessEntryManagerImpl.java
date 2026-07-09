package com.github.reganjohn.iam.internal.managers;

import com.github.adamorgan.jnt.api.utils.AccessUtil;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.AccessOptionData;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
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
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.AttributeKey;
import io.netty.util.HashedWheelTimer;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.Nonnull;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;
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
    public InteractionCallbackAction<Boolean> hasAccess(@Nonnull AccessObjectData rawData)
    {
        AccessOptionData optionData = rawData.getOptionData();
        Checks.check(MiscUtil.isUUID(optionData.getName()), ""); //todo: add message!
        UUID kid = UUID.fromString(optionData.getName());
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM users.public_keys WHERE kid = ?", Collections.singletonList(kid))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Boolean> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (array.isEmpty())
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SIGNER));
                else
                    interaction.onSuccess(hasAccess(array.getObject(0)));
            }

            private boolean hasAccess(@Nonnull BufferObject successObj) throws GeneralSecurityException
            {
                String mode = successObj.getString("alg");
                X509EncodedKeySpec engine = new X509EncodedKeySpec(successObj.getBytes("public_key"));
                KeyFactory factory = KeyFactory.getInstance(mode);
                PublicKey key = factory.generatePublic(engine);
                return AccessUtil.checkAccess(key, SignType.from(mode), rawData.getRawHeaders(), rawData.getRawBody(), rawData.getRawSign());
            }
        };
    }

    @Override
    protected void onCreateSnapshot(@Nonnull AccessEntrySnapshot snapshot)
    {
        String content = "INSERT INTO users.public_keys (kid, public_key, alg, created_at, expires_at) VALUES (:kid, :public_key, :alg, :created_at, :expires_at)";
        new InteractionMappingActionImpl<Void>(api.getJACT(), content, mapFromData(snapshot))
                .queue(success -> super.onCreateSnapshot(snapshot), Throwable::printStackTrace);
    }

    @Nonnull
    @Unmodifiable
    private Map<String, Object> mapFromData(@Nonnull AccessEntrySnapshot snapshot)
    {
        return new InteractionMapping.Builder()
                .put("kid", snapshot.getUniqueId())
                .put("public_key", snapshot.getPublicKey().getEncoded())
                .put("alg", getSignType().getName())
                .put("created_at", snapshot.getTimeCreated())
                .put("expires_at", snapshot.getTimeExpiresAt())
                .toMap();
    }
}
