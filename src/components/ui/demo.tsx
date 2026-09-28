"use client"

import LycorisSpecimen from "@/components/ui/lycoris-specimen"

export default function Demo() {
  // w-full is load-bearing: 21st centres every demo in a flex wrapper, and a
  // flex item left at width:auto shrinks to fit its contents — which, with a
  // child asking for 100%, resolves to 0px wide.
  return (
    <div className="w-full">
      <LycorisSpecimen />
    </div>
  )
}
