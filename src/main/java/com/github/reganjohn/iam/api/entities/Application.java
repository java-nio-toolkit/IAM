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

package com.github.reganjohn.iam.api.entities;

import com.github.adamorgan.jnt.api.entities.IUnique;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.interactions.AccessContextInteraction;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

public interface Application extends IUnique
{
    /** The maximum length for an application name ({@value}) */
    int MAX_NAME_LENGTH = 32;
    /** The maximum length for any Icon CID set on an application ({@value}) */
    int ICON_CID_MAX_LENGTH = 128;
    /** The maximum amount of URL that can be set to an application ({@value}) */
    int MAX_URL_COUNT = 5;
    /** The maximum length for any URL set on an application ({@value}) */
    int MAX_URL_LENGTH = 1 << 11;
    /** The maximum amount of access entry that can be set to an application ({@value}) */
    int MAX_ACCESS_ENTRY_COUNT = 10;
    /** The maximum length for an application description ({@value}) */
    int MAX_DESCRIPTION_LENGTH = 1 << 9;

    /**
     * The {@link IAM IAM} instance of this Application.
     *
     * @return The IAM instance of this Application
     */
    @Nonnull
    IAM getIAM();

    /**
     * The name of this application.
     * <br>The application name is <b>not</b> necessarily unique!
     *
     * @return The name of this application
     */
    @Nonnull
    String getName();

    /**
     * The description of this application.
     *
     * @return The description of this application or a null if no description is defined
     */
    @Nullable
    String getDescription();

    /**
     * The icon id of the application.
     *
     * @return The icon id of the application or null if no icon is defined
     */
    @Nullable
    String getIconId();

    /**
     * The id for the user who owns this
     *
     * @return The owner id of this application
     */
    @Nonnull
    UUID getOwnerId();

    /**
     * A {@link java.util.List} containing the GNAP redirect URIs of this application.
     *
     * <p>This List is empty if no redirect URIs are set.
     *
     * @return Immutable list containing the GNAP redirect URIs of this application
     */
    @Nonnull
    @Unmodifiable
    List<String> getRedirectUris();

    /**
     * The {@link ApplicationFlag Flags} set for the application.
     * <br>Modifying the returned EnumSet will have not actually change the flags of the application.
     *
     * @return {@link EnumSet} of {@link ApplicationFlag}
     */
    @Nonnull
    default EnumSet<ApplicationFlag> getFlags()
    {
        return ApplicationFlag.getFlags(getFlagsRaw());
    }

    @Nonnull
    InteractionCallbackAction<Void> delete();

    /**
     * The raw bitset representing this application's flags.
     *
     * @return The bitset
     */
    long getFlagsRaw();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Integer> retrieveAccessCount();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<AccessContextInteraction> retrieveAccessById(@Nonnull UUID accessId);

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<List<AccessContextInteraction>> retrieveAccess();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<ApplicationContextInteraction> retrieveInteractionById(@Nonnull UUID id);

    /**
     * Represents the bit offsets used for application flags.
     */
    enum ApplicationFlag
    {
        DELETED(34, false),
        UNKNOWN(-1, false);

        /**
         * Empty array of ApplicationFlag enum, useful for optimized use in {@link java.util.Collection#toArray(Object[])}.
         */
        public static final ApplicationFlag[] EMPTY_FLAGS = new ApplicationFlag[0];

        public static final long ALL = 1 | getRaw(EnumSet.allOf(ApplicationFlag.class));

        public static final long SYSTEM = ALL & ~getRaw();

        private final long offset;
        private final long raw;
        private final boolean managed;

        ApplicationFlag(long offset, boolean managed)
        {
            this.offset = offset;
            this.raw = 1L << offset;
            this.managed = managed;
        }

        /**
         * The binary offset of the flag.
         *
         * @return The offset that represents this {@link Application.ApplicationFlag ApplicationFlag}.
         */
        public long getOffset()
        {
            return offset;
        }

        /**
         * The value of this flag when viewed as raw value.
         * <br>This is equivalent to: <code>1 {@literal <<} {@link #getOffset()}</code>
         *
         * @return The raw value of this specific flag.
         */
        public long getRawValue()
        {
            return raw;
        }

        /**
         * Whether this {@link Application.ApplicationFlag ApplicationFlag} is managed.
         *
         * @return True, if this {@link Application.ApplicationFlag ApplicationFlag} is managed.
         */
        public boolean isManaged()
        {
            return managed;
        }

        /**
         * Gets the first ApplicationFlag relating to the provided offset.
         * <br>If there is no ApplicationFlag that matches the provided offset,
         * {@link #UNKNOWN} is returned.
         *
         * @param  offset
         *         The offset to match a ApplicationFlag to.
         *
         * @return ApplicationFlag relating to the provided offset.
         */
        @Nonnull
        public static ApplicationFlag getFromOffset(int offset)
        {
            for (ApplicationFlag flag : values())
            {
                if (flag.offset == offset)
                {
                    return flag;
                }
            }
            return UNKNOWN;
        }

        /**
         * A set of all ApplicationFlags that are specified by this raw int representation of
         * flags.
         *
         * @param  flags
         *         The raw {@code int} representation if flags.
         *
         * @return Possibly-empty EnumSet of ApplicationFlags.
         */
        @Nonnull
        public static EnumSet<ApplicationFlag> getFlags(long flags)
        {
            EnumSet<ApplicationFlag> foundFlags = EnumSet.noneOf(ApplicationFlag.class);
            if (flags == 0)
            {
                return foundFlags; // empty
            }
            for (ApplicationFlag flag : values())
            {
                if (flag != UNKNOWN && (flags & flag.raw) == flag.raw)
                {
                    foundFlags.add(flag);
                }
            }

            return foundFlags;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(long)}, this takes 1 or more ApplicationFlags
         * and returns the bitmask representation of the flags.
         *
         * @param  flags
         *         The array of flags of which to form into the raw int representation.
         *
         * @throws java.lang.IllegalArgumentException
         *         When the provided ApplicationFlags are null.
         *
         * @return bitmask representing the provided flags.
         */
        public static long getRaw(@Nonnull ApplicationFlag... flags)
        {
            Checks.noneNull(flags, "ApplicationFlags");
            long raw = 0;
            for (ApplicationFlag flag : flags)
            {
                if (flag != null && flag != UNKNOWN)
                {
                    raw |= flag.raw;
                }
            }

            return raw;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(long)}. This takes a collection of ApplicationFlags
         * and returns the bitmask representation of the flags.
         *
         * @param  flags
         *         The flags to convert
         *
         * @throws java.lang.IllegalArgumentException
         *         When the provided UserFLags are null.
         *
         * @return bitmask representing the provided flags.
         */
        public static long getRaw(@Nonnull Collection<ApplicationFlag> flags)
        {
            Checks.notNull(flags, "Flag Collection");
            return getRaw(flags.toArray(EMPTY_FLAGS));
        }
    }
}
