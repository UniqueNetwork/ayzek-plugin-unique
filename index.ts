import { ArgumentType, stringArgument } from '@ayzek/command-parser/arguments';
import { ParseEntryPoint } from '@ayzek/command-parser/command';
import { UserDisplayableError } from '@ayzek/command-parser/error';
import Reader from '@ayzek/command-parser/reader';
import { command, PluginBase } from '@ayzek/core/plugin';
import { AbstractSlots } from '@ayzek/linguist';
import { joinText, TextPart, Translation } from '@ayzek/text';
import { Component } from '@ayzek/text/component';
import { ApiPromise, WsProvider } from '@polkadot/api';
import Web3 from 'web3';
import type { Contract } from 'web3-eth-contract/types';
import * as io from 'io-ts';
import { addressToEvm, evmToAddress, isAddress, isEthereumAddress } from '@polkadot/util-crypto';
import { u8aToHex } from '@polkadot/util';

class ContractArgument extends ArgumentType<string, Contract> {
	constructor(public web3: Web3) {
		super();
	}
	parse<S>(ctx: ParseEntryPoint<S>, reader: Reader): string {
		const word = reader.readUnquotedString();
		if (!/^0x[0-9a-f]{40}$/i.test(word)) {
			throw new UserDisplayableError(`wrong address format: ${word}`);
		}
		return word;
	}
	async load(parsed: string): Promise<Contract> {
		try {
			if (await this.web3.eth.getCode(parsed) === '') {
				throw new UserDisplayableError(`contract not found, wrong network? ${parsed}`);
			}
			return new this.web3.eth.Contract([], parsed);
		} catch (e) {
			throw new UserDisplayableError('contract check failed, wrong network?\n' + (e as any).message);
		}
	}
}
const contractArgument = (web3: Web3) => new ContractArgument(web3);

class CollectionArgument extends ArgumentType<number, any> {
	constructor(public api: ApiPromise) {
		super();
	}
	parse<S>(ctx: ParseEntryPoint<S>, reader: Reader): number {
		return reader.readInt();
	}
	async load(parsed: number): Promise<number> {
		const collection = (await this.api.query.common.collectionById(parsed)) as any;
		if (collection.isNone)
			throw new Error('collection not found');
		return collection.unwrap().toJSON();
	}
}
const collectionArgument = (api: ApiPromise) => new CollectionArgument(api);

function asHexString(address: Buffer): string {
	return '0x' + address.toString('hex');
}

function collectionIdToAddress(address: number): string {
	if (address >= 0xffffffff || address < 0)
		throw new Error('id overflow');

	const buf = Buffer.from([0x17, 0xc4, 0xe6, 0x45, 0x3c, 0xc4, 0x9a, 0xaa, 0xae, 0xac, 0xa8, 0x94, 0xe6, 0xd9, 0x68, 0x3e,
		address >> 24,
		(address >> 16) & 0xff,
		(address >> 8) & 0xff,
		address & 0xff,
	]);
	return Web3.utils.toChecksumAddress(asHexString(buf));
}

const collection = ({ api, t }: Plugin) => command('collection')
	.thenArgument('collection', collectionArgument(api), b => {
		b.thenLiteral('check-sponsoring', b => {
			b.executes(async ctx => {
				const report = [];
				const collection = ctx.getArgument('collection') as any;

				if ('disabled' in collection.sponsorship) {
					report.push(t`⛔ Sponsoring is disabled`);
				} else if (collection.sponsorship.pending) {
					report.push(t`⛔ Sponsoring is pending\n${collection.sponsorship.pending} should confirm sponsoring via {code confirmSponsorship}`);
				} else if (collection.sponsorship.confirmed) {
					const address = collection.sponsorship.confirmed;
					const evmAddress = u8aToHex(addressToEvm(collection.sponsorship.confirmed));
					report.push(t`✅ Sponsor is confirmed`);
					{
						const balance = (await api.query.balances.account(address) as any).free.toBigInt();
						if (balance === 0n) {
							report.push(t`⛔ Substrate wallet of sponsor is empty\ntransfer some funds to {code ${address}}`);
						} else {
							report.push(t`✅ Sponsor has {token'opl'${balance}} on its substrate wallet`);
						}
					}
					{
						const balance = (await api.rpc.eth.getBalance(evmAddress)).toBigInt();
						if (balance === 0n) {
							report.push(t`⛔ Ethereum wallet of sponsor is empty\ntransfer some funds to {code ${evmAddress}}`);
						} else {
							report.push(t`✅ Sponsor has {token'opl'${balance}} on its ethereum wallet`);
						}
					}
				} else {
					report.push(t`🚸 Unknown sponsorship state: ${Object.keys(collection.sponsorship)[0]}`);
				}

				{
					const timeout = collection.limits.sponsorTransferTimeout;
					if (timeout === null || timeout !== 0) {
						report.push(t`🚸 Transfer timeout is ${timeout || 'not set (default, non-zero is used)'}`);
					} else {
						report.push(t`✅ Transfer timeout is zero blocks`);
					}
				}
				{
					const timeout = collection.limits.sponsorApproveTimeout;
					if (timeout === null || timeout !== 0) {
						report.push(t`🚸 Approve timeout is ${timeout || 'not set (default, non-zero is used)'}`);
					} else {
						report.push(t`✅ Approve timeout is zero blocks`);
					}
				}

				ctx.source.send([
					t`Check done, results:`, '\n',
					joinText('\n', report),
				]);
			}, 'Check collection sponsoring configuration');
		});

		b.thenLiteral('eth-address', b => {
			b.executes(async ctx => {
				const collection = ctx.getArgument('collection');
				const collectionAddress = collectionIdToAddress(collection);
				return t`Collection address:\n${collectionAddress}`;
			}, 'Get Ethereum collection address by id');
		});
	});

const evm = ({ api, web3, t }: Plugin) => command('evm')
	.thenLiteral('check-sponsoring', b => {
		b.thenArgument('contract', contractArgument(web3), b => {
			b.executes(async ctx => {
				const report = [];
				const address = ctx.getArgument('contract').options.address;

				if (!(await api.query.evmContractHelpers.selfSponsoring(address)).toJSON()) {
					report.push(t`⛔ Contract self-sponsoring is not enabled\nYou should call {code toggleSelfSponsoring} first`);
				} else {
					report.push(t`✅ Contract self-sponsoring is enabled`);
				}

				// TODO: Generous mode check
				const allowedUsers = await api.query.evmContractHelpers.allowlist.entries(address);
				if (allowedUsers.length === 0) {
					report.push(t`⛔ Allowlist is required for sponsoring, but it is empty for this contract\nMake sure you add wanted users using {code toggleAllowed}`);
				} else {
					report.push(t`✅ The following users are allowed to be sponsored:`);
					for (const [k, _] of allowedUsers) {
						const user = k.args[1];
						report.push(`- ${user}`);
					}
				}

				const currentBlock = (await api.query.system.number()).toJSON() as number;
				const rateLimit = (await api.query.evmContractHelpers.sponsoringRateLimit(address)).toJSON() as number;
				if (rateLimit !== 0) {
					report.push(t`🚸 Rate limit is not zero, users should wait ${rateLimit} blocks between calling sponsoring`);
					const out = [];
					const entries = await api.query.evmContractHelpers.sponsorBasket.entries(address);
					for (const [k, v] of entries) {
						const user = k.args[1].toString();
						const lastCall = v.toJSON() as number;
						if (lastCall + rateLimit >= currentBlock) {
							out.push(`- ${user} (${lastCall})`);
						}
					}
					if (out.length > 0) {
						report.push([
							'\n', t`The following users may be affected by this limitation (Last call block in braces):`, '\n',
							joinText('\n', out),
						]);
					}
				} else {
					report.push(t`✅ Rate limit is zero blocks`);
				}

				const balance = (await api.rpc.eth.getBalance(address)).toBigInt();
				if (balance === 0n) {
					report.push(t`⛔ Contract balance is zero, transactions will be failed via insufficient balance error`);
				} else {
					report.push(t`✅ Contract balance is {token'opl'${balance}}`);
				}

				ctx.source.send([
					t`Check done, results:`, '\n',
					joinText('\n', report),
				]);
			}, 'Check contract sponsoring configuration');
		});
		b.thenLiteral('test', b => {
			b.executes(async ctx => {
				const rateLimited = (await api.query.evmContractHelpers.sponsoringRateLimit.entries()).map(([k, v]) => [k.toString(), v.toJSON()]);
				ctx.source.send(JSON.stringify(rateLimited, null, 4));
			});
		});
	});

type Token = {
	decimalPoints: bigint;
	name: string;
};

const tokens: { [key: string]: Token } = {
	opl: {
		decimalPoints: 18n,
		name: 'OPL',
	},
};

/**
 * Formats passed value as token amount
 *
 * {token'name'{1}} where {1} - bigint
 */
class TokenComponent extends Component {
	token!: Token;
	amount!: number;
	setValue(value: string): void {
		if (this.token)
			throw new Error('token is already set');
		if (!tokens[value])
			throw new Error(`unknown token: ${value}`);
		this.token = tokens[value];
	}
	setSlot(slot: number): void {
		if (this.amount !== undefined)
			throw new Error('amount is already set');
		this.amount = slot;
	}
	validate(): void {
		if (!this.token)
			throw new Error('token is not set');
		if (this.amount === undefined)
			throw new Error('amount is not set');
	}

	localize(_locale: Translation, slots: AbstractSlots<TextPart>): TextPart {
		const amount = slots[this.amount] as bigint;
		return `${amount / (10n ** this.token.decimalPoints)} ${this.token.name}`;
	}
}

const networks = new Map([
	['OPL', 42],
	['QTZ', 255],
	['UNQ', 5855],
]);

const convert = ({ t }: Plugin) => command('convert')
	.thenLiteral('to', b => {
		b.thenLiteral('eth', b => {
			b.thenArgument('sub address', stringArgument('single_word'), b => {
				b.executes(async ctx => {
					const subAddress = ctx.getArgument('sub address');
					if (isAddress(subAddress)) {
						const ethAddressBytes = addressToEvm(subAddress);
						const ethAddress = Web3.utils.toChecksumAddress(asHexString(Buffer.from(ethAddressBytes)));
						return t`Ethereum address:\n${ethAddress}`;
					}

					return t`"${subAddress}" is not a Substrate address`;
				}, 'Convert Substrate address to Ethereum address');
			});
		});
	})
	.thenLiteral('from', b => {
		b.thenLiteral('eth', b => {
			b.thenArgument('eth address', stringArgument('single_word'), b => {
				b.thenLiteral('to', b => {
					b.thenArgument('network-id', stringArgument('single_word'), b => {
						b.executes(async ctx => {
							const networkId = ctx.getArgument('network-id');
							const networkPrefix = networks.get(networkId);
							if (typeof networkPrefix === 'undefined') {
								return t`Unsupported network id "${networkId}", supported: ${[...networks.keys()].join(', ')}`;
							}

							const ethAddress = ctx.getArgument('eth address');
							if (isEthereumAddress(ethAddress)) {
								const subAddress = evmToAddress(ethAddress, networkPrefix).toString();
								return t`Substrate address:\n${subAddress}`;
							}

							return t`"${ethAddress}" is not a Ethereum address`;
						}, 'Convert Ethereum address to specific Substrate network address');
					});
				});
				b.executes(async ctx => {
					const ethAddress = ctx.getArgument('eth address');
					if (isEthereumAddress(ethAddress)) {
						const subAddress = evmToAddress(ethAddress).toString();
						return t`Substrate address:\n${subAddress}`;
					}

					return t`"${ethAddress}" is not a Ethereum address`;
				}, 'Convert Ethereum address to common Substrate address');
			});
		});
	});

export default class Plugin extends PluginBase {
	name = 'UniqueNetwork';
	author = 'UniqueNetwork';
	description = this.t`Unique network helper plugin`;

	configType = io.interface({
		socketUrl: io.string,
	});
	defaultConfig = {
		socketUrl: 'wss://ws-quartz.unique.network',
	};
	config!: io.TypeOf<typeof this.configType>;

	commands = [collection, evm, convert];

	api!: ApiPromise;
	web3!: Web3;

	async init() {
		this.api = await ApiPromise.create({
			provider: new WsProvider(this.config.socketUrl),
		});
		this.web3 = new Web3(
			new Web3.providers.WebsocketProvider(this.config.socketUrl),
		);
	}
	async deinit() {
		this.api && await this.api.disconnect();
		this.web3 && await (this.web3.currentProvider! as any).disconnect(4000, 'plugin deinit');
	}

	translations = require.context('./translations', false, /\.json$/);
	components = { token: TokenComponent };
}
