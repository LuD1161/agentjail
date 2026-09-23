import { queryOptions } from '@tanstack/react-query'
import { fetchRequestDetail } from './api'
import type { RequestLog } from '../types'

export function selectedRequestQuery(id: number | null, local?: RequestLog) {
  return queryOptions({
    queryKey: ['request-detail', id],
    queryFn: () => {
      if (id === null) throw new Error('No request selected')
      return fetchRequestDetail(id)
    },
    enabled: id !== null && Number.isSafeInteger(id) && id > 0,
    initialData: local,
    gcTime: 0,
  })
}
