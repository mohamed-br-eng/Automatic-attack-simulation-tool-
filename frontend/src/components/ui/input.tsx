import * as React from 'react'
import { cn } from '@/lib/utils'
export function Input({
  className,
  type,
  ...props
}: React.ComponentProps<'input'>) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        'flex h-[34px] w-full rounded border border-[#454e5b] bg-[#191d24] px-3 py-1.5 text-xs placeholder:text-[#9aa5b5] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300 disabled:opacity-50',
        className,
      )}
      {...props}
    />
  )
}
