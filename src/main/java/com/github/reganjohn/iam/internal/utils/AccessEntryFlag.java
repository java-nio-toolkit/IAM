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

package com.github.reganjohn.iam.internal.utils;

import com.github.adamorgan.jnt.internal.utils.Checks;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.EnumSet;

public enum AccessEntryFlag
{
    ISSUED(1, false),
    APPLICATION(2, false),
    PRIVATE(3, false),
    DELETED(34, false),
    UNKNOWN(-1, false);

    /**
     * Empty array of AccessEntryFlag enum, useful for optimized use in {@link java.util.Collection#toArray(Object[])}.
     */
    public static final AccessEntryFlag[] EMPTY_FLAGS = new AccessEntryFlag[0];

    public static final long ALL = getRaw(EnumSet.allOf(AccessEntryFlag.class));

    public static final long SYSTEM = ALL & ~getRaw();

    private final long offset;
    private final long raw;
    private final boolean managed;

    AccessEntryFlag(long offset, boolean managed)
    {
        this.offset = offset;
        this.raw = 1L << offset;
        this.managed = managed;
    }

    /**
     * The binary offset of the flag.
     *
     * @return The offset that represents this {@link AccessEntryFlag AccessEntryFlag}.
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
     * Whether this {@link AccessEntryFlag AccessEntryFlag} is managed.
     *
     * @return True, if this {@link AccessEntryFlag AccessEntryFlag} is managed.
     */
    public boolean isManaged()
    {
        return managed;
    }

    /**
     * Gets the first AccessEntryFlag relating to the provided offset.
     * <br>If there is no AccessEntryFlag that matches the provided offset,
     * {@link #UNKNOWN} is returned.
     *
     * @param  offset
     *         The offset to match a AccessEntryFlag to.
     *
     * @return AccessEntryFlag relating to the provided offset.
     */
    @Nonnull
    public static AccessEntryFlag getFromOffset(int offset)
    {
        for (AccessEntryFlag flag : values())
        {
            if (flag.offset == offset)
            {
                return flag;
            }
        }
        return UNKNOWN;
    }

    /**
     * A set of all AccessEntryFlags that are specified by this raw int representation of
     * flags.
     *
     * @param  flags
     *         The raw {@code int} representation if flags.
     *
     * @return Possibly-empty EnumSet of AccessEntryFlags.
     */
    @Nonnull
    public static EnumSet<AccessEntryFlag> getFlags(long flags)
    {
        EnumSet<AccessEntryFlag> foundFlags = EnumSet.noneOf(AccessEntryFlag.class);
        if (flags == 0)
        {
            return foundFlags; // empty
        }
        for (AccessEntryFlag flag : values())
        {
            if (flag != UNKNOWN && (flags & flag.raw) == flag.raw)
            {
                foundFlags.add(flag);
            }
        }

        return foundFlags;
    }

    /**
     * This is effectively the opposite of {@link #getFlags(long)}, this takes 1 or more AccessEntryFlags
     * and returns the bitmask representation of the flags.
     *
     * @param  flags
     *         The array of flags of which to form into the raw int representation.
     *
     * @throws java.lang.IllegalArgumentException
     *         When the provided AccessEntryFlags are null.
     *
     * @return bitmask representing the provided flags.
     */
    public static long getRaw(@Nonnull AccessEntryFlag... flags)
    {
        Checks.noneNull(flags, "AccessEntryFlags");
        long raw = 0;
        for (AccessEntryFlag flag : flags)
        {
            if (flag != null && flag != UNKNOWN)
            {
                raw |= flag.raw;
            }
        }

        return raw;
    }

    /**
     * This is effectively the opposite of {@link #getFlags(long)}. This takes a collection of AccessEntryFlags
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
    public static long getRaw(@Nonnull Collection<AccessEntryFlag> flags)
    {
        Checks.notNull(flags, "Flag Collection");
        return getRaw(flags.toArray(EMPTY_FLAGS));
    }
}
