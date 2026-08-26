package com.github.reganjohn.iam.api.managers;

import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;

public interface GlobalAccessManager extends AccessEntryManager
{
    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Boolean> hasAccess(@Nonnull AccessObjectData data);

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Boolean> checkAvailable(@Nonnull String thumbprint);
}
