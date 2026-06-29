package com.github.reganjohn.iam.api.managers;

import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.AccessOptionData;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;

public interface GlobalAccessManager extends AccessEntryManager
{
    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Boolean> hasGlobalAccess(@Nonnull AccessObjectData rawData);
}
