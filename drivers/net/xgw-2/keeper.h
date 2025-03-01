
#ifndef __XGW_KEEPER__
#define __XGW_KEEPER__

//
#define KEEPER_INTERVAL ((9 * HZ) / 10)

// HASHEIA E AGRUPA POR INTERFACE INDEX
// NOTE: SE MUDAR DE INTERFACE VAI TER QUE REMOVER DA LISTA PRIMEIRO, E SÓ DEPOIS JOGAR PARA OUTRO
#define PING_QUEUES_N 8

static void keeper (struct timer_list* const timer);

#undef
