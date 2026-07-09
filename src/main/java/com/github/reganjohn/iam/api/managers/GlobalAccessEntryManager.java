package com.github.reganjohn.iam.api.managers;

import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;

public interface GlobalAccessEntryManager extends AccessEntryManager
{
    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Boolean> hasAccess(@Nonnull AccessObjectData rawData);
}
