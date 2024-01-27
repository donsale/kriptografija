// Copyright 2017 Elias Kosunen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is a part of scnlib:
//     https://github.com/eliaskosunen/scnlib

#pragma once

#include <scn/detail/error.h>
#include <scn/detail/ranges.h>
#include <scn/impl/util/internal_error.h>
#include <scn/util/memory.h>

namespace scn {
SCN_BEGIN_NAMESPACE

namespace impl {
#if !SCN_STD_RANGES && SCN_MSVC_DEBUG_ITERATORS
#define SCN_NEED_MS_DEBUG_ITERATOR_WORKAROUND 1
#else
#define SCN_NEED_MS_DEBUG_ITERATOR_WORKAROUND 0
#endif

template <typename T>
constexpr bool range_supports_nocopy() SCN_NOEXCEPT
{
#if SCN_NEED_MS_DEBUG_ITERATOR_WORKAROUND
    return ranges::contiguous_range<T> ||
           (ranges::random_access_range<T> &&
            detail::can_make_address_from_iterator<
                ranges::iterator_t<T>>::value);
#else
    return ranges::contiguous_range<T>;
#endif
}

template <typename R>
constexpr auto range_nocopy_data(R&& r) SCN_NOEXCEPT
{
    static_assert(range_supports_nocopy<R>());
#if SCN_NEED_MS_DEBUG_ITERATOR_WORKAROUND
    return detail::to_address(ranges::begin(SCN_FWD(r)));
#else
    return ranges::data(SCN_FWD(r));
#endif
}

template <typename R>
constexpr auto range_nocopy_size(R&& r) SCN_NOEXCEPT
{
    static_assert(range_supports_nocopy<R>());
#if SCN_NEED_MS_DEBUG_ITERATOR_WORKAROUND
    return static_cast<size_t>(
        ranges::distance(detail::to_address(ranges::begin(r)),
                         detail::to_address(ranges::end(r))));
#else
    return static_cast<size_t>(ranges::size(SCN_FWD(r)));
#endif
}

template <typename I, typename S>
SCN_NODISCARD constexpr bool is_range_eof(I begin, S end)
{
#if SCN_NEED_MS_DEBUG_ITERATOR_WORKAROUND
    if constexpr (ranges_std::contiguous_iterator<I> ||
                  (ranges_std::random_access_iterator<I> &&
                   detail::can_make_address_from_iterator<I>::value)) {
        return detail::to_address(begin) == detail::to_address(end);
    }
    else
#endif
    {
        return begin == end;
    }
}

template <typename Range>
SCN_NODISCARD constexpr bool is_range_eof(const Range& range)
{
    return is_range_eof(ranges::begin(range), ranges::end(range));
}

template <typename Range>
SCN_NODISCARD constexpr eof_error eof_check(const Range& range)
{
    if (SCN_UNLIKELY(is_range_eof(range))) {
        return eof_error::eof;
    }
    return eof_error::good;
}
}  // namespace impl

SCN_END_NAMESPACE
}  // namespace scn
