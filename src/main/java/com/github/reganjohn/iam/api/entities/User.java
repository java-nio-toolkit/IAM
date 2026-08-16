/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.api.entities;

import com.github.adamorgan.jnt.api.entities.IUnique;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.IAM;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

public interface User extends IUnique
{
    /** The minimum length for a username ({@value}) */
    int MIN_NAME_LENGTH = 2;
    /** The maximum length for a username ({@value}) */
    int MAX_NAME_LENGTH = 32;
    /** The maximum length for a avatar id ({@value}) */
    int AVATAR_CID_MAX_LENGTH = 128;

    /**
     * The username of the {@link User User}. Length is between 2 and 32 characters (inclusive).
     *
     * @return Never-null String containing the {@link User User}'s username.
     */
    @Nonnull
    String getName();

    /**
     * The {@link IAM IAM} instance of this User.
     *
     * @return The corresponding JDA instance
     */
    @Nonnull
    IAM getIAM();

    /**
     * The IPFS CID for this user's avatar image.
     * If the user has not set an image, this will return null.
     *
     * @return Possibly-null String containing the {@link com.github.reganjohn.iam.api.entities.User User} avatar id.
     */
    @Nullable
    String getAvatarId();

    /**
     * Returns the {@link UserFlag UserFlags} of this user.
     *
     * @return EnumSet containing the flags of the user.
     */
    @Nonnull
    default EnumSet<UserFlag> getFlags()
    {
        return UserFlag.getFlags(getFlagsRaw());
    }

    /**
     * Returns the bitmask representation of the {@link UserFlag UserFlags} of this user.
     *
     * @return bitmask representation of the user's flags.
     */
    long getFlagsRaw();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<List<AccessEntryData>> retrieveAccess();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<AccessEntryData> retrieveAccessById(@Nonnull String thumbprint);

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Session> retrieveSessionById(@Nonnull UUID sessionId);

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<List<Session>> retrieveSessions();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Integer> retrieveSessionCount();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Webhook> retrieveWebhookById(@Nonnull UUID webhookId);

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<List<Webhook>> retrieveWebhooks();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Integer> retrieveWebhookCount();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Application> retrieveApplicationById(@Nonnull UUID applicationId);

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<List<Application>> retrieveApplications();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Integer> retrieveApplicationCount();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<PermissionOverride> retrieveEntitlementById(@Nonnull UUID applicationId);

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<List<PermissionOverride>> retrieveEntitlements();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Void> delete();

    /**
     * Represents the bit offsets used for user flags.
     */
    enum UserFlag
    {
        DELETED(34, "User's account is deleted", false),
        UNKNOWN(-1, "Unknown", false);

        /**
         * Empty array of UserFlag enum, useful for optimized use in {@link java.util.Collection#toArray(Object[])}.
         */
        public static final UserFlag[] EMPTY_FLAGS = new UserFlag[0];

        public static final long ALL = 1 | getRaw(EnumSet.allOf(UserFlag.class));

        public static final long SYSTEM = ALL & ~getRaw();

        private final long offset;
        private final long raw;
        private final String name;
        private final boolean managed;

        UserFlag(long offset, @Nonnull String name)
        {
            this(offset, name, true);
        }

        UserFlag(long offset, @Nonnull String name, boolean managed)
        {
            this.offset = offset;
            this.raw = 1L << offset;
            this.name = name;
            this.managed = managed;
        }

        /**
         * The readable name as used in client.
         *
         * @return The readable name of this {@link UserFlag UserFlag}.
         */
        @Nonnull
        public String getName()
        {
            return this.name;
        }

        /**
         * Whether this {@link UserFlag UserFlag} is managed.
         *
         * @return True, if this {@link UserFlag UserFlag} is managed.
         */
        public boolean isManaged()
        {
            return managed;
        }

        /**
         * The binary offset of the flag.
         *
         * @return The offset that represents this {@link UserFlag UserFlag}.
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
         * Gets the first UserFlag relating to the provided offset.
         * <br>If there is no UserFlag that matches the provided offset,
         * {@link #UNKNOWN} is returned.
         *
         * @param  offset
         *         The offset to match a UserFlag to.
         *
         * @return UserFlag relating to the provided offset.
         */
        @Nonnull
        public static UserFlag getFromOffset(int offset)
        {
            for (UserFlag flag : values())
            {
                if (flag.offset == offset)
                {
                    return flag;
                }
            }
            return UNKNOWN;
        }

        /**
         * A set of all UserFlags that are specified by this raw int representation of
         * flags.
         *
         * @param  flags
         *         The raw {@code int} representation if flags.
         *
         * @return Possibly-empty EnumSet of UserFlags.
         */
        @Nonnull
        public static EnumSet<UserFlag> getFlags(long flags)
        {
            EnumSet<UserFlag> foundFlags = EnumSet.noneOf(UserFlag.class);
            if (flags == 0)
            {
                return foundFlags; // empty
            }
            for (UserFlag flag : values())
            {
                if (flag != UNKNOWN && (flags & flag.raw) == flag.raw)
                {
                    foundFlags.add(flag);
                }
            }

            return foundFlags;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(long)}, this takes 1 or more UserFlags
         * and returns the bitmask representation of the flags.
         *
         * @param  flags
         *         The array of flags of which to form into the raw int representation.
         *
         * @throws java.lang.IllegalArgumentException
         *         When the provided UserFlags are null.
         *
         * @return bitmask representing the provided flags.
         */
        public static long getRaw(@Nonnull UserFlag... flags)
        {
            Checks.noneNull(flags, "UserFlags");
            long raw = 0;
            for (UserFlag flag : flags)
            {
                if (flag != null && flag != UNKNOWN)
                {
                    raw |= flag.raw;
                }
            }

            return raw;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(long)}. This takes a collection of UserFlags
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
        public static long getRaw(@Nonnull Collection<UserFlag> flags)
        {
            Checks.notNull(flags, "Flag Collection");
            return getRaw(flags.toArray(EMPTY_FLAGS));
        }
    }
}
