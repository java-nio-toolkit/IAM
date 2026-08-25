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

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.Permission;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.EnumSet;
import java.util.UUID;

public interface PermissionOverride
{
    @Nonnull
    IAM getIAM();

    @Nonnull
    UUID getUserId();

    @Nonnull
    UUID getOwnerId();

    @Nonnull
    UUID getApplicationId();

    @Nonnull
    OffsetDateTime getTimeUpdated();

    @Nonnull
    default EnumSet<Permission> getPermissions()
    {
        return Permission.getPermissions(getPermissionsRaw());
    }

    long getPermissionsRaw();

    boolean hasPermission(@Nonnull Permission... permissions);

    default boolean hasPermission(@Nonnull Collection<Permission> permissions)
    {
        Checks.notNull(permissions, "Permissions");
        return hasPermission(permissions.toArray(Permission.EMPTY_PERMISSIONS));
    }

    @Nonnull
    default EnumSet<EntitlementFlag> getFlags()
    {
        return EntitlementFlag.getFlags(getFlagsRaw());
    }

    long getFlagsRaw();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Void> delete();

    enum EntitlementFlag
    {
        DELETED(34, false),
        UNKNOWN(-1, false);

        /**
         * Empty array of EntitlementFlag enum, useful for optimized use in {@link java.util.Collection#toArray(Object[])}.
         */
        public static final EntitlementFlag[] EMPTY_FLAGS = new EntitlementFlag[0];

        public static final long ALL = 1 | getRaw(EnumSet.allOf(EntitlementFlag.class));

        public static final long SYSTEM = ALL & ~getRaw();

        private final long offset;
        private final long raw;
        private final boolean managed;

        EntitlementFlag(long offset, boolean managed)
        {
            this.offset = offset;
            this.raw = 1L << offset;
            this.managed = managed;
        }

        /**
         * The binary offset of the flag.
         *
         * @return The offset that represents this {@link EntitlementFlag EntitlementFlag}.
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
         * Whether this {@link EntitlementFlag EntitlementFlag} is managed.
         *
         * @return True, if this {@link EntitlementFlag EntitlementFlag} is managed.
         */
        public boolean isManaged()
        {
            return managed;
        }

        /**
         * Gets the first EntitlementFlag relating to the provided offset.
         * <br>If there is no EntitlementFlag that matches the provided offset,
         * {@link #UNKNOWN} is returned.
         *
         * @param  offset
         *         The offset to match a EntitlementFlag to.
         *
         * @return EntitlementFlag relating to the provided offset.
         */
        @Nonnull
        public static EntitlementFlag getFromOffset(int offset)
        {
            for (EntitlementFlag flag : values())
            {
                if (flag.offset == offset)
                {
                    return flag;
                }
            }
            return UNKNOWN;
        }

        /**
         * A set of all EntitlementFlags that are specified by this raw int representation of
         * flags.
         *
         * @param  flags
         *         The raw {@code int} representation if flags.
         *
         * @return Possibly-empty EnumSet of EntitlementFlags.
         */
        @Nonnull
        public static EnumSet<EntitlementFlag> getFlags(long flags)
        {
            EnumSet<EntitlementFlag> foundFlags = EnumSet.noneOf(EntitlementFlag.class);
            if (flags == 0)
            {
                return foundFlags; // empty
            }
            for (EntitlementFlag flag : values())
            {
                if (flag != UNKNOWN && (flags & flag.raw) == flag.raw)
                {
                    foundFlags.add(flag);
                }
            }

            return foundFlags;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(long)}, this takes 1 or more EntitlementFlags
         * and returns the bitmask representation of the flags.
         *
         * @param  flags
         *         The array of flags of which to form into the raw int representation.
         *
         * @throws java.lang.IllegalArgumentException
         *         When the provided EntitlementFlags are null.
         *
         * @return bitmask representing the provided flags.
         */
        public static long getRaw(@Nonnull EntitlementFlag... flags)
        {
            Checks.noneNull(flags, "EntitlementFlags");
            long raw = 0;
            for (EntitlementFlag flag : flags)
            {
                if (flag != null && flag != UNKNOWN)
                {
                    raw |= flag.raw;
                }
            }

            return raw;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(long)}. This takes a collection of EntitlementFlags
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
        public static long getRaw(@Nonnull Collection<EntitlementFlag> flags)
        {
            Checks.notNull(flags, "Flag Collection");
            return getRaw(flags.toArray(EMPTY_FLAGS));
        }
    }
}
