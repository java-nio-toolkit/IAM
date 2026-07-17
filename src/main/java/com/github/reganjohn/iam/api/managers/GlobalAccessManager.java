package com.github.reganjohn.iam.api.managers;

import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.UUID;

public interface GlobalAccessManager extends AccessEntryManager
{
    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Boolean> hasAccess(@Nonnull UUID id, @Nonnull AccessObjectData data);
}
