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

package com.github.reganjohn.iam.api.events.applications.interactions;

import com.github.adamorgan.jnt.api.events.Event;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;

import javax.annotation.Nonnull;
import java.util.UUID;

public class GenericInteractionEvent extends Event
{
    private final ApplicationContextInteraction interaction;
    private final ApplicationInteractionType type;

    public GenericInteractionEvent(@Nonnull ApplicationContextInteraction interaction,
                                   @Nonnull ApplicationInteractionType type)
    {
        this.interaction = interaction;
        this.type = type;
    }

    @Nonnull
    public UUID getInteractionId()
    {
        return interaction.getUniqueId();
    }

    @Nonnull
    public UUID getUserId()
    {
        return interaction.getOwnerId();
    }

    @Nonnull
    public UUID getApplicationId()
    {
        return interaction.getApplicationId();
    }

    @Nonnull
    public ApplicationContextInteraction getInteraction()
    {
        return interaction;
    }

    @Nonnull
    public ApplicationInteractionType getType()
    {
        return type;
    }

    @Nonnull
    public DataObject getRawData()
    {
        return DataObject.empty()
                .put("interaction_id", getInteractionId())
                .put("user_id", getUserId())
                .put("application_id", getApplicationId())
                .put("type", getType())
                .toData();
    }
}
